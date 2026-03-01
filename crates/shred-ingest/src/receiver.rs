//! UDP multicast shred receiver.
//!
//! Binds to a UDP socket, joins the DoubleZero multicast group, and emits
//! raw shred bytes with a nanosecond receive timestamp.
//!
//! ## Hot-path design (Linux)
//! * `SO_BUSY_POLL 50µs` — spin-waits for packets, eliminates scheduler wakeup latency
//! * `SO_TIMESTAMPNS` — kernel captures receive timestamp at NIC driver level,
//!   before any userspace scheduling jitter; more accurate than `clock_gettime` after `recv`
//! * `recvmmsg(MSG_WAITFORONE, batch=64)` — returns as soon as ≥1 packet is available,
//!   filling more if already queued; reduces syscall overhead at high packet rates
//! * `SO_RCVBUFFORCE 32MB` — bypasses `net.core.rmem_max`; falls back to `SO_RCVBUF`
//!   with a warning if not running as root

use anyhow::Result;
use crossbeam_channel::Sender;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use crate::metrics;
use crate::shred_race::ShredArrival;
use crate::source_metrics::SourceMetrics;

/// Raw shred bytes received from UDP multicast.
pub struct RawShred {
    pub data: Vec<u8>,
    pub recv_timestamp_ns: u64,
}

/// Event sent from the UDP receiver hot-path to the capture thread.
/// The channel is bounded(4096); `try_send` never blocks — packets are
/// silently dropped on overflow rather than stalling the hot path.
pub struct CaptureEvent {
    pub ts_ns: u64,
    pub feed: &'static str,
    pub dst_ip: [u8; 4],
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

pub struct ShredReceiver {
    socket: Socket,
    tx: Sender<RawShred>,
    metrics: Arc<SourceMetrics>,
    /// Optional shred version filter (bytes 77-78). Shreds with a different
    /// version are silently dropped before they reach the decoder.
    shred_version: Option<u16>,
    /// CLOCK_REALTIME − CLOCK_MONOTONIC_RAW sampled at construction time (ns).
    /// Applied to every SO_TIMESTAMPNS kernel timestamp to bring it into the
    /// CLOCK_MONOTONIC_RAW reference frame used by the rest of the pipeline.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    rt_to_mono_offset_ns: u64,
    /// Optional channel to the shred race tracker. Each received shred's
    /// (slot, shred_index) is forwarded here for cross-feed comparison.
    race_tx: Option<Sender<ShredArrival>>,
    /// Optional channel to the capture thread. Receives a copy of every raw
    /// shred packet; drops silently on overflow to protect the hot path.
    capture_tx: Option<Sender<CaptureEvent>>,
    /// Multicast destination IP stored for capture event metadata.
    dst_ip: [u8; 4],
    /// UDP destination port stored for capture event metadata.
    dst_port: u16,
}

// Standard Solana shred MTU — used by both Linux and fallback paths.
const PKT_CAP: usize = 1500;

// Linux hot-path constants.
// Batch size for recvmmsg. 64 is a common sweet-spot: enough to amortise
// syscall overhead without holding packets in kernel longer than necessary.
#[cfg(target_os = "linux")]
const BATCH: usize = 64;
// cmsg buffer: cmsghdr (16B) + timespec (16B) + alignment padding = 64B is safe.
#[cfg(target_os = "linux")]
const CMSG_CAP: usize = 64;
// MSG_WAITFORONE: return as soon as ≥1 message is available, fill more if queued.
// Value 0x10000 from <linux/socket.h>; may not be exposed by the libc crate version.
#[cfg(target_os = "linux")]
const MSG_WAITFORONE: libc::c_int = 0x10000;

impl ShredReceiver {
    /// Bind to the multicast group on the specified interface.
    pub fn new(
        multicast_addr: &str,
        port: u16,
        interface: &str,
        tx: Sender<RawShred>,
        metrics: Arc<SourceMetrics>,
        shred_version: Option<u16>,
        race_tx: Option<Sender<ShredArrival>>,
        capture_tx: Option<Sender<CaptureEvent>>,
    ) -> Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        // Note: SO_REUSEPORT is intentionally NOT set. With SO_REUSEPORT, the
        // kernel hashes (src_ip, src_port) to distribute packets across sockets
        // sharing a port. Because all DoubleZero shreds arrive from the same relay
        // IP:port, every packet hashes to the same socket — one source gets all
        // traffic and the other gets none. SO_REUSEADDR alone is sufficient here:
        // each socket binds to a distinct multicast address so they don't conflict.

        let mcast_addr: Ipv4Addr = multicast_addr.parse()?;
        let iface_addr = Self::resolve_interface_addr(interface)?;
        let bind_addr = SocketAddrV4::new(mcast_addr, port);
        socket.bind(&bind_addr.into())?;
        socket.join_multicast_v4(&mcast_addr, &iface_addr)?;

        #[cfg(target_os = "linux")]
        {
            use std::mem::size_of;
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            unsafe {
                // SO_BUSY_POLL: spin for up to 50µs before blocking.
                let val: libc::c_int = 50;
                libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BUSY_POLL,
                    &val as *const _ as _, size_of::<libc::c_int>() as _);

                // SO_RCVBUFFORCE: bypasses net.core.rmem_max (requires root).
                // Falls back to SO_RCVBUF with a warning if unprivileged.
                const RECV_BUF: usize = 32 * 1024 * 1024;
                let buf_val = RECV_BUF as libc::c_int;
                let force_ok = libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE,
                    &buf_val as *const _ as _, size_of::<libc::c_int>() as _) == 0;
                if !force_ok {
                    socket.set_recv_buffer_size(RECV_BUF).ok();
                    if let Ok(actual) = socket.recv_buffer_size() {
                        if actual < RECV_BUF / 2 {
                            tracing::warn!(
                                "recv buffer is {}KB (wanted {}KB); \
                                 run as root or: sysctl -w net.core.rmem_max={}",
                                actual / 1024, RECV_BUF / 1024, RECV_BUF * 2
                            );
                        }
                    }
                }

                // SO_TIMESTAMPNS: kernel records the receive timestamp at NIC
                // driver level, returned via SCM_TIMESTAMPNS cmsg on recvmsg/recvmmsg.
                let one: libc::c_int = 1;
                libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMPNS,
                    &one as *const _ as _, size_of::<libc::c_int>() as _);
            }
        }

        #[cfg(not(target_os = "linux"))]
        socket.set_recv_buffer_size(4 * 1024 * 1024)?;

        let rt_to_mono_offset_ns = sample_rt_to_mono_offset_ns();
        let dst_ip = mcast_addr.octets();

        Ok(Self {
            socket,
            tx,
            metrics,
            shred_version,
            rt_to_mono_offset_ns,
            race_tx,
            capture_tx,
            dst_ip,
            dst_port: port,
        })
    }

    /// Main receive loop — should run on a pinned, isolated core.
    pub fn run(&mut self) -> Result<()> {
        tracing::info!("shred receiver started");

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = self.socket.as_raw_fd();
            self.run_linux(fd)
        }

        #[cfg(not(target_os = "linux"))]
        self.run_fallback()
    }

    /// Linux hot path: recvmmsg with kernel timestamps.
    #[cfg(target_os = "linux")]
    fn run_linux(&mut self, fd: libc::c_int) -> Result<()> {
        use std::ptr::null_mut;
        // Pre-allocate batch buffers once; pointers into these are held by
        // iovs/msgs for the lifetime of the loop.
        let mut pkts = vec![[0u8; PKT_CAP]; BATCH];
        let mut cmsgs = vec![[0u8; CMSG_CAP]; BATCH];
        let mut iovs: Vec<libc::iovec> = pkts
            .iter_mut()
            .map(|b| libc::iovec { iov_base: b.as_mut_ptr() as _, iov_len: PKT_CAP })
            .collect();
        let mut msgs: Vec<libc::mmsghdr> = (0..BATCH)
            .map(|i| libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: null_mut(),
                    msg_namelen: 0,
                    msg_iov: &mut iovs[i] as *mut _,
                    msg_iovlen: 1,
                    msg_control: cmsgs[i].as_mut_ptr() as _,
                    msg_controllen: CMSG_CAP,
                    msg_flags: 0,
                },
                msg_len: 0,
            })
            .collect();

        loop {
            // Reset fields that recvmmsg may have modified.
            for (i, msg) in msgs.iter_mut().enumerate() {
                msg.msg_hdr.msg_controllen = CMSG_CAP;
                msg.msg_hdr.msg_iov = &mut iovs[i] as *mut _;
                iovs[i].iov_len = PKT_CAP;
            }

            let n = unsafe {
                libc::recvmmsg(fd, msgs.as_mut_ptr(), BATCH as _, MSG_WAITFORONE, null_mut())
            };
            if n <= 0 {
                continue;
            }

            for i in 0..n as usize {
                let len = msgs[i].msg_len as usize;
                if len == 0 {
                    continue;
                }

                // Shred version filter: bytes 77-78 (u16 LE) carry the fork ID.
                if let Some(ver) = self.shred_version {
                    if len >= 79 {
                        let v = u16::from_le_bytes([pkts[i][77], pkts[i][78]]);
                        if v != ver {
                            continue;
                        }
                    }
                }

                // Prefer kernel timestamp (CLOCK_REALTIME) converted to
                // CLOCK_MONOTONIC_RAW; fall back to userspace clock.
                let ts = kernel_ts(&msgs[i].msg_hdr)
                    .map(|rt| rt.saturating_sub(self.rt_to_mono_offset_ns))
                    .unwrap_or_else(metrics::now_ns);

                // Shred race: parse (slot, shred_index) from the shred header.
                // Layout: bytes 65–72 = slot (u64 LE), 73–76 = shred_index (u32 LE).
                if len >= 77 {
                    if let Some(ref rtx) = self.race_tx {
                        let slot = u64::from_le_bytes(pkts[i][65..73].try_into().unwrap());
                        let idx = u32::from_le_bytes(pkts[i][73..77].try_into().unwrap());
                        let _ = rtx.try_send(ShredArrival {
                            source: self.metrics.name,
                            slot,
                            idx,
                            recv_ns: ts,
                        });
                    }
                }

                // Capture tap: clone raw bytes to the capture thread.
                // try_send never blocks; silent drop on channel overflow.
                if let Some(ref ctx) = self.capture_tx {
                    let _ = ctx.try_send(CaptureEvent {
                        ts_ns: ts,
                        feed: self.metrics.name,
                        dst_ip: self.dst_ip,
                        dst_port: self.dst_port,
                        payload: pkts[i][..len].to_vec(),
                    });
                }

                self.metrics.shreds_received.fetch_add(1, Relaxed);
                self.metrics.bytes_received.fetch_add(len as u64, Relaxed);

                if self.tx.try_send(RawShred {
                    data: pkts[i][..len].to_vec(),
                    recv_timestamp_ns: ts,
                }).is_err() {
                    self.metrics.shreds_dropped.fetch_add(1, Relaxed);
                }
            }
        }
    }

    /// Non-Linux fallback: single recv per loop iteration.
    #[cfg(not(target_os = "linux"))]
    fn run_fallback(&mut self) -> Result<()> {
        let mut buf = vec![0u8; PKT_CAP];
        loop {
            let buf_uninit: &mut [std::mem::MaybeUninit<u8>] = unsafe {
                std::slice::from_raw_parts_mut(buf.as_mut_ptr() as _, buf.len())
            };
            let n = self.socket.recv(buf_uninit)?;
            let ts = metrics::now_ns();
            if n == 0 { continue; }

            if let Some(ver) = self.shred_version {
                if n >= 79 {
                    let v = u16::from_le_bytes([buf[77], buf[78]]);
                    if v != ver { continue; }
                }
            }

            // Shred race: parse (slot, shred_index) from the shred header.
            if n >= 77 {
                if let Some(ref rtx) = self.race_tx {
                    let slot = u64::from_le_bytes(buf[65..73].try_into().unwrap());
                    let idx = u32::from_le_bytes(buf[73..77].try_into().unwrap());
                    let _ = rtx.try_send(ShredArrival {
                        source: self.metrics.name,
                        slot,
                        idx,
                        recv_ns: ts,
                    });
                }
            }

            // Capture tap.
            if let Some(ref ctx) = self.capture_tx {
                let _ = ctx.try_send(CaptureEvent {
                    ts_ns: ts,
                    feed: self.metrics.name,
                    dst_ip: self.dst_ip,
                    dst_port: self.dst_port,
                    payload: buf[..n].to_vec(),
                });
            }

            self.metrics.shreds_received.fetch_add(1, Relaxed);
            self.metrics.bytes_received.fetch_add(n as u64, Relaxed);
            if self.tx.try_send(RawShred {
                data: buf[..n].to_vec(),
                recv_timestamp_ns: ts,
            }).is_err() {
                self.metrics.shreds_dropped.fetch_add(1, Relaxed);
            }
        }
    }

    fn resolve_interface_addr(interface: &str) -> Result<Ipv4Addr> {
        #[cfg(target_os = "linux")]
        {
            use std::ffi::CStr;
            use std::ptr::null_mut;
            unsafe {
                let mut addrs: *mut libc::ifaddrs = null_mut();
                if libc::getifaddrs(&mut addrs) != 0 {
                    anyhow::bail!("getifaddrs failed");
                }
                let mut current = addrs;
                while !current.is_null() {
                    let ifa = &*current;
                    if !ifa.ifa_name.is_null() && !ifa.ifa_addr.is_null() {
                        let name = CStr::from_ptr(ifa.ifa_name).to_str().unwrap_or("");
                        if name == interface
                            && (*ifa.ifa_addr).sa_family == libc::AF_INET as libc::sa_family_t
                        {
                            let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                            libc::freeifaddrs(addrs);
                            return Ok(ip);
                        }
                    }
                    current = ifa.ifa_next;
                }
                libc::freeifaddrs(addrs);
            }
            anyhow::bail!("interface {} not found", interface);
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = interface;
            Ok(Ipv4Addr::LOCALHOST)
        }
    }
}

/// Sample CLOCK_REALTIME − CLOCK_MONOTONIC_RAW once at startup.
///
/// SO_TIMESTAMPNS delivers CLOCK_REALTIME timestamps. Subtracting this offset
/// converts them into the CLOCK_MONOTONIC_RAW frame used by `metrics::now_ns()`.
/// The offset is stable over the service lifetime (NTP slew is negligible vs
/// our ~300 ms lead times). We take the minimum of 8 paired samples to reduce
/// the effect of scheduler preemption between the two `clock_gettime` calls.
fn sample_rt_to_mono_offset_ns() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let read_rt = || unsafe {
            let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
            ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
        };
        let read_mono = || unsafe {
            let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut ts);
            ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
        };
        // Read RT then MONO in tight succession; take min over 8 rounds to
        // minimise preemption-induced inflation of the difference.
        (0..8)
            .map(|_| read_rt().saturating_sub(read_mono()))
            .min()
            .unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Extract the kernel receive timestamp from a recvmmsg control message.
///
/// SO_TIMESTAMPNS makes the kernel deliver a `struct timespec` in a
/// `SCM_TIMESTAMPNS` cmsg (cmsg_type == SO_TIMESTAMPNS == 35 on Linux).
/// Returns `None` if the cmsg is absent (e.g. SO_TIMESTAMPNS not set).
#[cfg(target_os = "linux")]
fn kernel_ts(hdr: &libc::msghdr) -> Option<u64> {
    // SAFETY: hdr.msg_control points to our pre-allocated cmsg buffer;
    // CMSG_* macros walk the buffer using the controllen field.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(hdr) };
    while !cmsg.is_null() {
        let c = unsafe { &*cmsg };
        // SCM_TIMESTAMPNS == SO_TIMESTAMPNS == 35 on all Linux arches.
        if c.cmsg_level == libc::SOL_SOCKET && c.cmsg_type == libc::SO_TIMESTAMPNS {
            let ts: libc::timespec = unsafe {
                std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const libc::timespec)
            };
            return Some(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64);
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(hdr, cmsg) };
    }
    None
}
