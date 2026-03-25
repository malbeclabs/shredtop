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
    /// Source IPv4 in network byte order (big-endian u32). Zero if unavailable.
    pub src_ip: u32,
}

pub struct ShredReceiver {
    socket: Socket,
    tx: Sender<RawShred>,
    metrics: Arc<SourceMetrics>,
    /// Optional shred version filter (bytes 77-78). Shreds with a different
    /// version are silently dropped before they reach the decoder.
    shred_version: Option<u16>,
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

        let dst_ip = mcast_addr.octets();

        Ok(Self {
            socket,
            tx,
            metrics,
            shred_version,
            race_tx,
            capture_tx,
            dst_ip,
            dst_port: port,
        })
    }

    /// Bind to a unicast UDP port with SO_REUSEPORT.
    ///
    /// Used for the `turbine` source type: binds `0.0.0.0:port` and sets
    /// `SO_REUSEPORT` so the socket can coexist with a running validator's TVU
    /// socket on the same port. Turbine shreds arrive from many different
    /// retransmit nodes (varied src IPs), so the kernel's per-flow hash
    /// distributes them across both sockets — shredtop receives a representative
    /// sample with accurate kernel timestamps, sufficient for lead-time measurement.
    pub fn new_unicast(
        port: u16,
        tx: Sender<RawShred>,
        metrics: Arc<SourceMetrics>,
        shred_version: Option<u16>,
        race_tx: Option<Sender<ShredArrival>>,
        capture_tx: Option<Sender<CaptureEvent>>,
    ) -> Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;

        // SO_REUSEPORT allows sharing this port with the validator's TVU socket.
        // Unlike the multicast case (where all shreds come from one relay IP),
        // turbine shreds originate from many retransmit nodes, so the per-flow
        // hash distributes traffic across sockets rather than sending all packets
        // to a single socket. Set via libc directly — socket2 0.5 requires a
        // feature flag for set_reuse_port().
        #[cfg(target_os = "linux")]
        {
            use std::mem::size_of;
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            unsafe {
                let one: libc::c_int = 1;
                libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT,
                    &one as *const _ as _, size_of::<libc::c_int>() as _);
            }
        }

        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        socket.bind(&bind_addr.into())?;
        // No multicast group join — turbine shreds are unicast to the validator's IP.

        #[cfg(target_os = "linux")]
        {
            use std::mem::size_of;
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            unsafe {
                let val: libc::c_int = 50;
                libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BUSY_POLL,
                    &val as *const _ as _, size_of::<libc::c_int>() as _);

                const RECV_BUF: usize = 32 * 1024 * 1024;
                let buf_val = RECV_BUF as libc::c_int;
                let force_ok = libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE,
                    &buf_val as *const _ as _, size_of::<libc::c_int>() as _) == 0;
                if !force_ok {
                    socket.set_recv_buffer_size(RECV_BUF).ok();
                }

                let one: libc::c_int = 1;
                libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMPNS,
                    &one as *const _ as _, size_of::<libc::c_int>() as _);
            }
        }

        #[cfg(not(target_os = "linux"))]
        socket.set_recv_buffer_size(4 * 1024 * 1024)?;

        Ok(Self {
            socket,
            tx,
            metrics,
            shred_version,
            race_tx,
            capture_tx,
            dst_ip: [0, 0, 0, 0],
            dst_port: port,
        })
    }

    /// Bind to a generic unicast UDP address.
    ///
    /// Used for the `unicast` source type: receives shreds forwarded by a relay
    /// (e.g. a shredder UDP output) or any unicast UDP forwarder. Unlike turbine,
    /// this does NOT set SO_REUSEPORT — it binds exclusively to `addr:port`.
    ///
    /// `addr` is the local bind address (e.g. `"0.0.0.0"` or a specific IP).
    /// `port` is the UDP port to listen on.
    pub fn new_generic_unicast(
        addr: &str,
        port: u16,
        tx: Sender<RawShred>,
        metrics: Arc<SourceMetrics>,
        shred_version: Option<u16>,
        race_tx: Option<Sender<ShredArrival>>,
        capture_tx: Option<Sender<CaptureEvent>>,
    ) -> Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        // No SO_REUSEPORT — exclusive bind to this address.
        // No multicast group join — unicast only.

        let bind_ip: Ipv4Addr = addr.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
        let bind_addr = SocketAddrV4::new(bind_ip, port);
        socket.bind(&bind_addr.into())?;

        #[cfg(target_os = "linux")]
        {
            use std::mem::size_of;
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            unsafe {
                let val: libc::c_int = 50;
                libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BUSY_POLL,
                    &val as *const _ as _, size_of::<libc::c_int>() as _);

                const RECV_BUF: usize = 32 * 1024 * 1024;
                let buf_val = RECV_BUF as libc::c_int;
                let force_ok = libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE,
                    &buf_val as *const _ as _, size_of::<libc::c_int>() as _) == 0;
                if !force_ok {
                    socket.set_recv_buffer_size(RECV_BUF).ok();
                }

                let one: libc::c_int = 1;
                libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMPNS,
                    &one as *const _ as _, size_of::<libc::c_int>() as _);
            }
        }

        #[cfg(not(target_os = "linux"))]
        socket.set_recv_buffer_size(4 * 1024 * 1024)?;

        Ok(Self {
            socket,
            tx,
            metrics,
            shred_version,
            race_tx,
            capture_tx,
            dst_ip: bind_ip.octets(),
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
        // Pre-allocate source address buffers. recvmmsg fills msg_name with
        // sockaddr_in for each received packet, giving us the sender's IPv4.
        let mut src_addrs: Vec<libc::sockaddr_in> =
            (0..BATCH).map(|_| unsafe { std::mem::zeroed() }).collect();
        let mut iovs: Vec<libc::iovec> = pkts
            .iter_mut()
            .map(|b| libc::iovec { iov_base: b.as_mut_ptr() as _, iov_len: PKT_CAP })
            .collect();
        let src_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let mut msgs: Vec<libc::mmsghdr> = (0..BATCH)
            .map(|i| libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: &mut src_addrs[i] as *mut _ as *mut libc::c_void,
                    msg_namelen: src_namelen,
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
                msg.msg_hdr.msg_namelen = src_namelen;
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

                // DoubleZero heartbeat: 4-byte magic "DZ\x00\x01" (0x44 0x5A 0x00 0x01).
                // Arrives on the same socket as shreds; skip the shred pipeline.
                if len >= 4
                    && pkts[i][0] == 0x44
                    && pkts[i][1] == 0x5A
                    && pkts[i][2] == 0x00
                    && pkts[i][3] == 0x01
                {
                    self.metrics.last_heartbeat_ns.store(metrics::now_ns(), Relaxed);
                    continue;
                }

                // Minimum shred size: common header (65B) + coding header end (89B).
                // Data shreds need 88B; coding shreds need 89B — use 89 for both.
                // Anything shorter is malformed and cannot be parsed.
                if len < 89 {
                    self.metrics.shreds_invalid.fetch_add(1, Relaxed);
                    continue;
                }

                // Variant byte (offset 64) must be a known data or coding value.
                // Unknown variants indicate garbage UDP payloads — drop before decoder.
                let variant = pkts[i][64];
                let is_data = variant == 0xa5
                    || matches!(variant & 0xF0, 0x80 | 0x90 | 0xa0 | 0xb0);
                let is_code = matches!(variant & 0xF0, 0x40 | 0x50 | 0x60 | 0x70)
                    && variant != 0x5a;
                if !is_data && !is_code {
                    self.metrics.shreds_invalid.fetch_add(1, Relaxed);
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

                // Prefer kernel SO_TIMESTAMPNS (CLOCK_REALTIME); fall back to
                // userspace CLOCK_REALTIME. Both shred and RPC timestamps use
                // CLOCK_REALTIME so lead time comparisons are on the same clock.
                let ts = kernel_ts(&msgs[i].msg_hdr)
                    .unwrap_or_else(metrics::now_realtime_ns);

                // Source IP: sin_addr.s_addr is already big-endian (network byte order).
                let src_ip = src_addrs[i].sin_addr.s_addr;

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
                            src_ip,
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
                        src_ip,
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
            let (n, peer_addr) = self.socket.recv_from(buf_uninit)?;
            let src_ip: u32 = peer_addr
                .as_socket_ipv4()
                .map(|a| u32::from_be_bytes(a.ip().octets()))
                .unwrap_or(0);
            let ts = metrics::now_ns();
            if n == 0 { continue; }

            // DoubleZero heartbeat check.
            if n >= 4 && buf[0] == 0x44 && buf[1] == 0x5A && buf[2] == 0x00 && buf[3] == 0x01 {
                self.metrics.last_heartbeat_ns.store(ts, Relaxed);
                continue;
            }

            // Minimum length + variant validation.
            if n < 89 {
                self.metrics.shreds_invalid.fetch_add(1, Relaxed);
                continue;
            }
            let variant = buf[64];
            let is_data = variant == 0xa5 || matches!(variant & 0xF0, 0x80 | 0x90 | 0xa0 | 0xb0);
            let is_code = matches!(variant & 0xF0, 0x40 | 0x50 | 0x60 | 0x70) && variant != 0x5a;
            if !is_data && !is_code {
                self.metrics.shreds_invalid.fetch_add(1, Relaxed);
                continue;
            }

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
                        src_ip,
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
                    src_ip,
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

    /// Spawn a thread that auto-detects the DoubleZero heartbeat port by
    /// sniffing the interface, then listens on it permanently. DZ sends
    /// heartbeats on the same multicast group but a different UDP port than
    /// shred data, so the main receiver socket never sees them.
    ///
    /// If `heartbeat_port` is `Some`, skips detection and uses that port.
    /// Otherwise probes the interface for up to 5 seconds with `AF_PACKET`,
    /// falling back to port 5765 if no heartbeat is detected.
    pub fn spawn_heartbeat_listener(
        multicast_addr: String,
        interface: String,
        metrics: Arc<SourceMetrics>,
        name: &'static str,
        heartbeat_port: Option<u16>,
    ) -> Result<std::thread::JoinHandle<()>> {
        let handle = std::thread::Builder::new()
            .name(format!("{}-heartbeat", name))
            .spawn(move || {
                let port = heartbeat_port.unwrap_or_else(|| {
                    eprintln!("{name}: probing {interface} for DZ heartbeat port...");
                    match detect_heartbeat_port(&interface) {
                        Some(p) => {
                            eprintln!("{name}: detected DZ heartbeat on port {p}");
                            p
                        }
                        None => {
                            eprintln!(
                                "{name}: no DZ heartbeat detected on {interface}, \
                                 falling back to port 5765"
                            );
                            5765
                        }
                    }
                });

                let mcast_addr: Ipv4Addr = match multicast_addr.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("{name}: heartbeat: bad multicast addr: {e}");
                        return;
                    }
                };
                let iface_addr = match Self::resolve_interface_addr(&interface) {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("{name}: heartbeat: resolve interface: {e}");
                        return;
                    }
                };
                let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("{name}: heartbeat: socket create: {e}");
                        return;
                    }
                };
                socket.set_reuse_address(true).ok();
                socket.set_recv_buffer_size(64 * 1024).ok();
                let bind_addr = SocketAddrV4::new(mcast_addr, port);
                if let Err(e) = socket.bind(&bind_addr.into()) {
                    eprintln!("{name}: heartbeat bind {mcast_addr}:{port}: {e}");
                    return;
                }
                if let Err(e) = socket.join_multicast_v4(&mcast_addr, &iface_addr) {
                    eprintln!("{name}: heartbeat join multicast: {e}");
                    return;
                }

                eprintln!("{name}: heartbeat listener on {multicast_addr}:{port}");
                let mut buf = [0u8; 64];
                loop {
                    let buf_uninit: &mut [std::mem::MaybeUninit<u8>] = unsafe {
                        std::slice::from_raw_parts_mut(buf.as_mut_ptr() as _, buf.len())
                    };
                    match socket.recv(buf_uninit) {
                        Ok(n) if n >= 4 => {
                            if buf[0] == 0x44
                                && buf[1] == 0x5A
                                && buf[2] == 0x00
                                && buf[3] == 0x01
                            {
                                metrics.last_heartbeat_ns.store(
                                    crate::metrics::now_ns(),
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                            }
                        }
                        _ => {}
                    }
                }
            })?;

        Ok(handle)
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

/// Sniff the interface with `AF_PACKET` for up to 5 seconds looking for
/// DoubleZero heartbeat packets (4-byte UDP, magic `DZ\x00\x01`).
/// Returns the UDP destination port if found.
#[cfg(target_os = "linux")]
fn detect_heartbeat_port(interface: &str) -> Option<u16> {
    use std::time::{Duration, Instant};

    const PROBE_SECS: u64 = 5;

    // AF_PACKET + SOCK_DGRAM: all IP frames on the interface, link header stripped.
    let sock = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM,
            (libc::ETH_P_IP as u16).to_be() as libc::c_int,
        )
    };
    if sock < 0 {
        return None;
    }

    // Look up interface index.
    let ifindex = {
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let name = interface.as_bytes();
        let n = name.len().min(libc::IFNAMSIZ - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                ifr.ifr_name.as_mut_ptr() as *mut u8,
                n,
            );
            if libc::ioctl(sock, libc::SIOCGIFINDEX, &ifr) < 0 {
                libc::close(sock);
                return None;
            }
            ifr.ifr_ifru.ifru_ifindex
        }
    };

    // Bind to the interface.
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    sll.sll_ifindex = ifindex;
    unsafe {
        if libc::bind(
            sock,
            &sll as *const _ as _,
            std::mem::size_of_val(&sll) as u32,
        ) < 0
        {
            libc::close(sock);
            return None;
        }
    }

    // Recv timeout — slightly longer than probe window so the loop's
    // Instant check is the effective deadline.
    let tv = libc::timeval { tv_sec: (PROBE_SECS + 1) as libc::time_t, tv_usec: 0 };
    unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as _,
            std::mem::size_of_val(&tv) as u32,
        );
    }

    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(PROBE_SECS);

    let result = loop {
        if Instant::now() >= deadline {
            break None;
        }
        let n = unsafe { libc::recv(sock, buf.as_mut_ptr() as _, buf.len(), 0) };
        if n <= 0 {
            break None;
        }
        let n = n as usize;

        // IP header: byte 0 low nibble = IHL (words), byte 9 = protocol.
        if n < 28 {
            continue; // 20 (IP min) + 8 (UDP hdr)
        }
        let ihl = ((buf[0] & 0x0F) as usize) * 4;
        if buf[9] != 17 || n < ihl + 12 {
            continue; // not UDP or too short
        }

        // UDP header at offset ihl: src_port(2) dst_port(2) length(2) checksum(2).
        let dst_port = u16::from_be_bytes([buf[ihl + 2], buf[ihl + 3]]);
        let udp_len = u16::from_be_bytes([buf[ihl + 4], buf[ihl + 5]]) as usize;
        let payload_start = ihl + 8;
        let payload_len = udp_len.saturating_sub(8);

        if payload_len == 4
            && n >= payload_start + 4
            && buf[payload_start] == 0x44
            && buf[payload_start + 1] == 0x5A
            && buf[payload_start + 2] == 0x00
            && buf[payload_start + 3] == 0x01
        {
            break Some(dst_port);
        }
    };

    unsafe { libc::close(sock); }
    result
}

/// Non-Linux stub — heartbeat detection requires `AF_PACKET`.
#[cfg(not(target_os = "linux"))]
fn detect_heartbeat_port(_interface: &str) -> Option<u16> {
    None
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
