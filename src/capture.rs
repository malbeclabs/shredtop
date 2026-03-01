//! Always-on ring-buffer capture subsystem.
//!
//! Receives raw shred packets from the UDP receiver hot-path via a bounded
//! channel and writes them to disk in the configured format (pcap, csv, jsonl).
//! Rotation and ring-buffer management happen inside the capture thread so the
//! hot path is never blocked.

use crate::config::CaptureConfig;
use crossbeam_channel::Receiver;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::{DataLink, Endianness, TsResolution};
use shred_ingest::CaptureEvent;
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{info, warn};

// ─── Writer trait ────────────────────────────────────────────────────────────

pub trait CaptureWriter: Send {
    fn write_shred(
        &mut self,
        ts_ns: u64,
        feed: &str,
        dst_ip: [u8; 4],
        dst_port: u16,
        payload: &[u8],
    ) -> io::Result<()>;

    fn flush(&mut self) -> io::Result<()>;
}

// ─── Rotation state ──────────────────────────────────────────────────────────

/// Tracks the ring-buffer of on-disk capture files.
///
/// The active (currently-writing) file is always `shreds.{ext}`.  When it
/// fills, it is renamed to `shreds.{ext}.{N}` and a fresh active file is
/// opened.  The oldest archived file is deleted once the ring exceeds
/// `ring_files` entries.
struct RotationState {
    dir: PathBuf,
    ext: &'static str,
    max_bytes: u64,
    ring_files: usize,
    current_bytes: u64,
    next_gen: u32,
    ring: VecDeque<PathBuf>,
}

impl RotationState {
    fn new(output_dir: &str, ext: &'static str, rotate_mb: u64, ring_files: usize) -> Self {
        Self {
            dir: PathBuf::from(output_dir),
            ext,
            max_bytes: rotate_mb * 1024 * 1024,
            ring_files,
            current_bytes: 0,
            next_gen: 1,
            ring: VecDeque::new(),
        }
    }

    fn active_path(&self) -> PathBuf {
        self.dir.join(format!("shreds.{}", self.ext))
    }

    fn should_rotate(&self, incoming: usize) -> bool {
        self.current_bytes + incoming as u64 > self.max_bytes
    }

    /// Rename the active file to the next archive slot; evict oldest if needed.
    fn rotate(&mut self) -> io::Result<()> {
        let active = self.active_path();
        let archive = self.dir.join(format!("shreds.{}.{}", self.ext, self.next_gen));
        if active.exists() {
            fs::rename(&active, &archive)?;
            info!("capture: archived {} → {}", active.display(), archive.display());
        }
        self.ring.push_back(archive);
        self.next_gen += 1;
        self.current_bytes = 0;

        if self.ring.len() > self.ring_files {
            if let Some(old) = self.ring.pop_front() {
                match fs::remove_file(&old) {
                    Ok(()) => info!("capture: deleted old file {}", old.display()),
                    Err(e) => warn!("capture: delete {} failed: {}", old.display(), e),
                }
            }
        }
        Ok(())
    }

    fn account(&mut self, n: usize) {
        self.current_bytes += n as u64;
    }
}

// ─── pcap writer ─────────────────────────────────────────────────────────────

pub struct PcapCaptureWriter {
    writer: Option<PcapWriter<BufWriter<File>>>,
    rotation: RotationState,
}

impl PcapCaptureWriter {
    pub fn new(output_dir: &str, rotate_mb: u64, ring_files: usize) -> io::Result<Self> {
        fs::create_dir_all(output_dir)?;
        let rotation = RotationState::new(output_dir, "pcap", rotate_mb, ring_files);
        let writer = open_pcap_writer(&rotation.active_path())?;
        Ok(Self { writer: Some(writer), rotation })
    }
}

fn ns_pcap_header() -> PcapHeader {
    PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: 65535,
        datalink: DataLink::ETHERNET,
        ts_resolution: TsResolution::NanoSecond,
        endianness: Endianness::native(),
    }
}

fn open_pcap_writer(path: &Path) -> io::Result<PcapWriter<BufWriter<File>>> {
    let file = File::create(path)?;
    PcapWriter::with_header(BufWriter::new(file), ns_pcap_header())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}

/// Build a minimal Ethernet + IPv4 + UDP frame wrapping the raw shred payload.
///
/// `dst_ip` = multicast group address — this is what identifies the feed in
/// Wireshark without any custom dissector.
fn build_frame(dst_ip: [u8; 4], dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = (8u16 + payload.len() as u16).to_be_bytes();
    let ip_total = (20u16 + 8 + payload.len() as u16).to_be_bytes();

    // Ethernet header (14 bytes): multicast MAC derived from group IP.
    let dst_mac = [0x01, 0x00, 0x5e, dst_ip[1] & 0x7f, dst_ip[2], dst_ip[3]];
    let src_mac = [0u8; 6];
    let ethertype = [0x08u8, 0x00]; // IPv4

    // IPv4 header (20 bytes, no options, checksum=0).
    let ip_hdr = [
        0x45, 0x00,
        ip_total[0], ip_total[1],
        0x00, 0x00, // ID
        0x00, 0x00, // flags/fragment
        64, 0x11,   // TTL=64, proto=UDP
        0x00, 0x00, // checksum
        0x00, 0x00, 0x00, 0x00, // src=0.0.0.0
        dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
    ];

    // UDP header (8 bytes).
    let udp_hdr = [
        0x00, 0x00, // src port=0
        (dst_port >> 8) as u8, dst_port as u8,
        udp_len[0], udp_len[1],
        0x00, 0x00, // checksum=0
    ];

    let mut frame = Vec::with_capacity(14 + 20 + 8 + payload.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ethertype);
    frame.extend_from_slice(&ip_hdr);
    frame.extend_from_slice(&udp_hdr);
    frame.extend_from_slice(payload);
    frame
}

impl CaptureWriter for PcapCaptureWriter {
    fn write_shred(
        &mut self,
        ts_ns: u64,
        _feed: &str,
        dst_ip: [u8; 4],
        dst_port: u16,
        payload: &[u8],
    ) -> io::Result<()> {
        let frame = build_frame(dst_ip, dst_port, payload);
        let frame_len = frame.len();

        if self.rotation.should_rotate(frame_len) {
            // Dropping the PcapWriter flushes its BufWriter before the rename.
            self.writer = None;
            self.rotation.rotate()?;
            self.writer = Some(open_pcap_writer(&self.rotation.active_path())?);
        }

        let timestamp = Duration::new(ts_ns / 1_000_000_000, (ts_ns % 1_000_000_000) as u32);
        if let Some(ref mut w) = self.writer {
            let pkt = PcapPacket::new(timestamp, frame_len as u32, &frame);
            w.write_packet(&pkt)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        }
        self.rotation.account(frame_len);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        // BufWriter flushes on rotation (via drop) and on process exit.
        Ok(())
    }
}

// ─── CSV writer ──────────────────────────────────────────────────────────────

pub struct CsvCaptureWriter {
    writer: BufWriter<File>,
    rotation: RotationState,
}

impl CsvCaptureWriter {
    pub fn new(output_dir: &str, rotate_mb: u64, ring_files: usize) -> io::Result<Self> {
        fs::create_dir_all(output_dir)?;
        let rotation = RotationState::new(output_dir, "csv", rotate_mb, ring_files);
        let mut writer = BufWriter::new(File::create(rotation.active_path())?);
        writeln!(writer, "recv_ns,feed,slot,shred_idx")?;
        Ok(Self { writer, rotation })
    }
}

impl CaptureWriter for CsvCaptureWriter {
    fn write_shred(
        &mut self,
        ts_ns: u64,
        feed: &str,
        _dst_ip: [u8; 4],
        _dst_port: u16,
        payload: &[u8],
    ) -> io::Result<()> {
        let slot = if payload.len() >= 73 {
            u64::from_le_bytes(payload[65..73].try_into().unwrap())
        } else {
            0
        };
        let idx = if payload.len() >= 77 {
            u32::from_le_bytes(payload[73..77].try_into().unwrap())
        } else {
            0
        };
        let line = format!("{},{},{},{}\n", ts_ns, feed, slot, idx);
        let line_len = line.len();

        if self.rotation.should_rotate(line_len) {
            self.writer.flush()?;
            self.rotation.rotate()?;
            self.writer = BufWriter::new(File::create(self.rotation.active_path())?);
            writeln!(self.writer, "recv_ns,feed,slot,shred_idx")?;
        }

        self.writer.write_all(line.as_bytes())?;
        self.rotation.account(line_len);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

// ─── JSONL writer ────────────────────────────────────────────────────────────

pub struct JsonlCaptureWriter {
    writer: BufWriter<File>,
    rotation: RotationState,
}

impl JsonlCaptureWriter {
    pub fn new(output_dir: &str, rotate_mb: u64, ring_files: usize) -> io::Result<Self> {
        fs::create_dir_all(output_dir)?;
        let rotation = RotationState::new(output_dir, "jsonl", rotate_mb, ring_files);
        let writer = BufWriter::new(File::create(rotation.active_path())?);
        Ok(Self { writer, rotation })
    }
}

impl CaptureWriter for JsonlCaptureWriter {
    fn write_shred(
        &mut self,
        ts_ns: u64,
        feed: &str,
        _dst_ip: [u8; 4],
        _dst_port: u16,
        payload: &[u8],
    ) -> io::Result<()> {
        let slot = if payload.len() >= 73 {
            u64::from_le_bytes(payload[65..73].try_into().unwrap())
        } else {
            0
        };
        let idx = if payload.len() >= 77 {
            u32::from_le_bytes(payload[73..77].try_into().unwrap())
        } else {
            0
        };
        let line = format!(
            "{{\"recv_ns\":{},\"feed\":\"{}\",\"slot\":{},\"shred_idx\":{}}}\n",
            ts_ns, feed, slot, idx
        );
        let line_len = line.len();

        if self.rotation.should_rotate(line_len) {
            self.writer.flush()?;
            self.rotation.rotate()?;
            self.writer = BufWriter::new(File::create(self.rotation.active_path())?);
        }

        self.writer.write_all(line.as_bytes())?;
        self.rotation.account(line_len);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

// ─── Capture thread ──────────────────────────────────────────────────────────

// ─── Multi-format fan-out writer ─────────────────────────────────────────────

struct MultiWriter {
    writers: Vec<Box<dyn CaptureWriter>>,
}

impl CaptureWriter for MultiWriter {
    fn write_shred(
        &mut self,
        ts_ns: u64,
        feed: &str,
        dst_ip: [u8; 4],
        dst_port: u16,
        payload: &[u8],
    ) -> io::Result<()> {
        for w in &mut self.writers {
            w.write_shred(ts_ns, feed, dst_ip, dst_port, payload)?;
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        for w in &mut self.writers {
            w.flush()?;
        }
        Ok(())
    }
}

fn make_writer(config: &CaptureConfig) -> Box<dyn CaptureWriter> {
    let writers: Vec<Box<dyn CaptureWriter>> = config
        .formats
        .iter()
        .enumerate()
        .map(|(idx, fmt)| -> Box<dyn CaptureWriter> {
            let ring = config.ring_files_for(idx);
            match fmt.as_str() {
                "csv" => Box::new(
                    CsvCaptureWriter::new(&config.output_dir, config.rotate_mb, ring)
                        .expect("failed to create CSV capture writer"),
                ),
                "jsonl" => Box::new(
                    JsonlCaptureWriter::new(&config.output_dir, config.rotate_mb, ring)
                        .expect("failed to create JSONL capture writer"),
                ),
                _ => Box::new(
                    PcapCaptureWriter::new(&config.output_dir, config.rotate_mb, ring)
                        .expect("failed to create pcap capture writer"),
                ),
            }
        })
        .collect();
    Box::new(MultiWriter { writers })
}

/// Spawn the background capture thread and return immediately.
///
/// The thread drains `rx`, writes each event via the configured writer, and
/// handles rotation/ring-buffer management internally. It runs for the lifetime
/// of the process.
pub fn spawn_capture_thread(
    config: &CaptureConfig,
    rx: Receiver<CaptureEvent>,
) -> std::thread::JoinHandle<()> {
    let mut writer = make_writer(config);

    std::thread::Builder::new()
        .name("capture".into())
        .spawn(move || {
            for event in &rx {
                if let Err(e) = writer.write_shred(
                    event.ts_ns,
                    event.feed,
                    event.dst_ip,
                    event.dst_port,
                    &event.payload,
                ) {
                    warn!("capture write error: {}", e);
                }
            }
        })
        .expect("failed to spawn capture thread")
}
