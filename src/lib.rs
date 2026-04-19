use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const FRAME_DURATION_NS: u64 = 20_000_000; // 20ms
const MAX_PACKET_SIZE: usize = 4096;
const DEFAULT_BUFFER_DURATION_MS: u32 = 400;
const PREALLOCATED_QUEUES: usize = 64;

// Discord voice constants
const RTP_HEADER_SIZE: usize = 12;

fn queue_capacity_from_ms(buffer_duration_ms: u32) -> usize {
    ((buffer_duration_ms as usize) / 20).max(1)
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// Discord voice encryption modes
#[derive(Clone, Debug)]
enum EncryptionMode {
    Aes256Gcm,
    XChaCha20Poly1305,
}

impl EncryptionMode {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "aead_aes256_gcm_rtpsize" => Some(EncryptionMode::Aes256Gcm),
            "aead_xchacha20_poly1305_rtpsize" => Some(EncryptionMode::XChaCha20Poly1305),
            _ => None,
        }
    }
}

/// Per-queue voice encryption state.
/// JS is the single source of truth for sequence/timestamp/nonce —
/// those are passed per-frame via push_encrypted_frame.
/// This struct only holds the static crypto material.
struct VoiceCryptoState {
    secret_key: [u8; 32],
    ssrc: u32,
    encryption_mode: EncryptionMode,
}

/// Build a 12-byte RTP header into `out[0..12]`.
fn write_rtp_header(out: &mut [u8], sequence: u16, timestamp: u32, ssrc: u32) {
    out[0] = 0x80; // version 2, no padding, no extension, 0 CSRC
    out[1] = 0x78; // payload type 120 (Discord voice)
    out[2..4].copy_from_slice(&sequence.to_be_bytes());
    out[4..8].copy_from_slice(&timestamp.to_be_bytes());
    out[8..12].copy_from_slice(&ssrc.to_be_bytes());
}

/// Encrypt `plaintext` using the given crypto state, RTP header as AAD,
/// and the caller-supplied nonce/sequence/timestamp.
/// Writes the fully-formed packet (RTP header || ciphertext+tag || nonce_trailer)
/// into `out`. Returns the total packet length on success.
fn encrypt_and_pack(
    crypto: &VoiceCryptoState,
    plaintext: &[u8],
    sequence: u16,
    timestamp: u32,
    nonce_value: u32,
    out: &mut [u8],
) -> Result<usize> {
    // Write RTP header
    write_rtp_header(out, sequence, timestamp, crypto.ssrc);
    let rtp_header = &out[0..RTP_HEADER_SIZE];

    match &crypto.encryption_mode {
        EncryptionMode::Aes256Gcm => {
            // 12-byte nonce: 4 bytes of counter (big-endian) + 8 zero bytes
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[0..4].copy_from_slice(&nonce_value.to_be_bytes());
            let nonce = Nonce::from_slice(&nonce_bytes);

            let cipher = Aes256Gcm::new_from_slice(&crypto.secret_key)
                .map_err(|e| napi::Error::from_reason(format!("AES key error: {e}")))?;

            let ciphertext = cipher
                .encrypt(nonce, Payload {
                    msg: plaintext,
                    aad: rtp_header,
                })
                .map_err(|e| napi::Error::from_reason(format!("AES-GCM encrypt failed: {e}")))?;

            // Packet layout: RTP header (12) || ciphertext+tag || nonce trailer (4)
            let total_len = RTP_HEADER_SIZE + ciphertext.len() + 4;
            if total_len > out.len() {
                return Err(napi::Error::from_reason("Packet too large for buffer"));
            }

            out[RTP_HEADER_SIZE..RTP_HEADER_SIZE + ciphertext.len()]
                .copy_from_slice(&ciphertext);
            out[RTP_HEADER_SIZE + ciphertext.len()..total_len]
                .copy_from_slice(&nonce_value.to_be_bytes());

            Ok(total_len)
        }
        EncryptionMode::XChaCha20Poly1305 => {
            // 24-byte nonce: 4 bytes of counter (big-endian) + 20 zero bytes
            let mut nonce_bytes = [0u8; 24];
            nonce_bytes[0..4].copy_from_slice(&nonce_value.to_be_bytes());
            let nonce = XNonce::from_slice(&nonce_bytes);

            let cipher = XChaCha20Poly1305::new_from_slice(&crypto.secret_key)
                .map_err(|e| napi::Error::from_reason(format!("XChaCha key error: {e}")))?;

            let ciphertext = cipher
                .encrypt(nonce, Payload {
                    msg: plaintext,
                    aad: rtp_header,
                })
                .map_err(|e| {
                    napi::Error::from_reason(format!("XChaCha20 encrypt failed: {e}"))
                })?;

            // Packet layout: RTP header (12) || ciphertext+tag || nonce trailer (4)
            let total_len = RTP_HEADER_SIZE + ciphertext.len() + 4;
            if total_len > out.len() {
                return Err(napi::Error::from_reason("Packet too large for buffer"));
            }

            out[RTP_HEADER_SIZE..RTP_HEADER_SIZE + ciphertext.len()]
                .copy_from_slice(&ciphertext);
            out[RTP_HEADER_SIZE + ciphertext.len()..total_len]
                .copy_from_slice(&nonce_value.to_be_bytes());

            Ok(total_len)
        }
    }
}

// ---------------------------------------------------------------------------
// Ring buffer
// ---------------------------------------------------------------------------

struct PacketSlot {
    data: [u8; MAX_PACKET_SIZE],
    len: usize,
}

impl Default for PacketSlot {
    fn default() -> Self {
        Self {
            data: [0u8; MAX_PACKET_SIZE],
            len: 0,
        }
    }
}

struct RingBuffer {
    slots: Vec<PacketSlot>,
    capacity: usize,
    head: usize,
    tail: usize,
    count: usize,
}

impl RingBuffer {
    fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);

        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(PacketSlot::default());
        }

        Self {
            slots,
            capacity,
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    fn push(&mut self, data: &[u8]) -> bool {
        if self.count >= self.capacity || data.len() > MAX_PACKET_SIZE {
            return false;
        }

        let slot = &mut self.slots[self.head];
        slot.data[..data.len()].copy_from_slice(data);
        slot.len = data.len();

        self.head = (self.head + 1) % self.capacity;
        self.count += 1;
        true
    }

    fn pop(&mut self) -> Option<&[u8]> {
        if self.count == 0 {
            return None;
        }

        let tail = self.tail;
        let len = self.slots[tail].len;

        self.tail = (self.tail + 1) % self.capacity;
        self.count -= 1;

        Some(&self.slots[tail].data[..len])
    }

    fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn len(&self) -> usize {
        self.count
    }

    fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
}

// ---------------------------------------------------------------------------
// Queue internals
// ---------------------------------------------------------------------------

struct QueueInner {
    buffer: RingBuffer,
    addr: SockAddr,
    active_index: Option<usize>,
    /// When Some, this queue is a "voice queue" that accepts raw Opus frames
    /// via push_encrypted_frame and handles RTP header + encryption natively.
    voice_crypto: Option<VoiceCryptoState>,
}

struct QueueManagerInner {
    queues: Vec<Option<QueueInner>>,
    active_keys: Vec<u32>,
}

impl QueueManagerInner {
    fn new() -> Self {
        Self {
            queues: Vec::with_capacity(PREALLOCATED_QUEUES),
            active_keys: Vec::with_capacity(PREALLOCATED_QUEUES),
        }
    }

    fn get_queue(&self, key: u32) -> Option<&QueueInner> {
        self.queues.get(key as usize)?.as_ref()
    }

    fn get_queue_mut(&mut self, key: u32) -> Option<&mut QueueInner> {
        self.queues.get_mut(key as usize)?.as_mut()
    }

    fn insert_queue(&mut self, queue: QueueInner) -> Result<u32> {
        let key =
            u32::try_from(self.queues.len()).map_err(|_| napi::Error::from_reason("Too many queues"))?;
        self.queues.push(Some(queue));
        Ok(key)
    }

    fn activate_queue(&mut self, key: u32) {
        let idx = key as usize;

        let already_active = match self.queues.get(idx).and_then(|q| q.as_ref()) {
            Some(queue) => queue.active_index.is_some(),
            None => return,
        };

        if already_active {
            return;
        }

        let pos = self.active_keys.len();
        self.active_keys.push(key);

        if let Some(Some(queue)) = self.queues.get_mut(idx) {
            queue.active_index = Some(pos);
        }
    }

    fn deactivate_active_key_at(&mut self, pos: usize) {
        if pos >= self.active_keys.len() {
            return;
        }

        let removed_key = self.active_keys[pos];

        if let Some(queue) = self.get_queue_mut(removed_key) {
            queue.active_index = None;
        }

        self.active_keys.swap_remove(pos);

        if pos < self.active_keys.len() {
            let moved_key = self.active_keys[pos];
            if let Some(moved_queue) = self.get_queue_mut(moved_key) {
                moved_queue.active_index = Some(pos);
            }
        }
    }

    fn deactivate_queue(&mut self, key: u32) {
        let pos = match self.get_queue(key).and_then(|q| q.active_index) {
            Some(pos) => pos,
            None => return,
        };

        self.deactivate_active_key_at(pos);
    }

    fn remove_queue(&mut self, key: u32) -> bool {
        let idx = key as usize;

        if idx >= self.queues.len() || self.queues[idx].is_none() {
            return false;
        }

        self.deactivate_queue(key);
        self.queues[idx] = None;
        true
    }
}

struct PendingPacket {
    len: usize,
    addr: SockAddr,
}

// ---------------------------------------------------------------------------
// Platform-specific timing
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod platform {
    use super::*;
    use windows_sys::Win32::Media::{timeBeginPeriod, timeEndPeriod};
    use windows_sys::Win32::System::Threading::{
        GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_TIME_CRITICAL,
    };

    pub struct TimerResolutionGuard;

    impl TimerResolutionGuard {
        pub fn new() -> Self {
            unsafe {
                let _ = timeBeginPeriod(1);
            }
            Self
        }
    }

    impl Drop for TimerResolutionGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = timeEndPeriod(1);
            }
        }
    }

    pub struct SleepContext;

    impl SleepContext {
        pub fn new() -> Self {
            Self
        }
    }

    pub fn set_current_thread_priority() {
        unsafe {
            let thread = GetCurrentThread();
            let _ = SetThreadPriority(thread, THREAD_PRIORITY_TIME_CRITICAL);
        }
    }

    pub fn precise_sleep_until(target: Instant, _ctx: &SleepContext) {
        if target <= Instant::now() {
            return;
        }

        let remaining = target.saturating_duration_since(Instant::now());
        let coarse = remaining.saturating_sub(Duration::from_micros(1000));

        if !coarse.is_zero() {
            thread::sleep(coarse);
        }

        while Instant::now() < target {
            std::hint::spin_loop();
            thread::yield_now();
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use libc::{clock_gettime, clock_nanosleep, pthread_self, pthread_setschedparam};
    use libc::{sched_param, timespec, CLOCK_MONOTONIC, EINTR, SCHED_FIFO, TIMER_ABSTIME};

    pub struct TimerResolutionGuard;

    impl TimerResolutionGuard {
        pub fn new() -> Self {
            Self
        }
    }

    pub struct SleepContext {
        base_instant: Instant,
        base_timespec: timespec,
    }

    impl SleepContext {
        pub fn new() -> Self {
            let mut ts = timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };

            unsafe {
                clock_gettime(CLOCK_MONOTONIC, &mut ts);
            }

            Self {
                base_instant: Instant::now(),
                base_timespec: ts,
            }
        }
    }

    fn add_duration(ts: timespec, dur: Duration) -> timespec {
        let mut sec = ts.tv_sec + dur.as_secs() as libc::time_t;
        let mut nsec = ts.tv_nsec + dur.subsec_nanos() as libc::c_long;

        if nsec >= 1_000_000_000 {
            sec += 1;
            nsec -= 1_000_000_000;
        }

        timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        }
    }

    pub fn set_current_thread_priority() {
        unsafe {
            let mut param: sched_param = std::mem::zeroed();
            param.sched_priority = 10;
            let _ = pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
        }
    }

    pub fn precise_sleep_until(target: Instant, ctx: &SleepContext) {
        if target <= Instant::now() {
            return;
        }

        let delta = target.saturating_duration_since(ctx.base_instant);
        let abs_target = add_duration(ctx.base_timespec, delta);

        loop {
            let rc = unsafe {
                clock_nanosleep(
                    CLOCK_MONOTONIC,
                    TIMER_ABSTIME,
                    &abs_target,
                    std::ptr::null_mut(),
                )
            };

            if rc == 0 {
                break;
            }

            if rc != EINTR {
                break;
            }
        }
    }
}

#[cfg(all(not(windows), not(target_os = "linux")))]
mod platform {
    use super::*;

    pub struct TimerResolutionGuard;

    impl TimerResolutionGuard {
        pub fn new() -> Self {
            Self
        }
    }

    pub struct SleepContext;

    impl SleepContext {
        pub fn new() -> Self {
            Self
        }
    }

    pub fn set_current_thread_priority() {
        // no-op
    }

    pub fn precise_sleep_until(target: Instant, _ctx: &SleepContext) {
        let now = Instant::now();
        if target > now {
            thread::sleep(target - now);
        }
    }
}

// ---------------------------------------------------------------------------
// Sender thread
// ---------------------------------------------------------------------------

fn sender_thread(
    inner: Arc<Mutex<QueueManagerInner>>,
    socket: Arc<Socket>,
    running: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
    packets_dropped: Arc<AtomicU64>,
) {
    let _timer_resolution = platform::TimerResolutionGuard::new();
    let sleep_ctx = platform::SleepContext::new();
    platform::set_current_thread_priority();

    let frame_duration = Duration::from_nanos(FRAME_DURATION_NS);

    let mut pending: Vec<PendingPacket> = Vec::with_capacity(PREALLOCATED_QUEUES);
    let mut send_bufs: Vec<[u8; MAX_PACKET_SIZE]> = Vec::with_capacity(PREALLOCATED_QUEUES);

    for _ in 0..PREALLOCATED_QUEUES {
        send_bufs.push([0u8; MAX_PACKET_SIZE]);
    }

    let mut next_tick = Instant::now();

    while running.load(Ordering::Acquire) {
        next_tick += frame_duration;
        pending.clear();

        {
            let mut guard = inner.lock().unwrap();

            let mut i = 0;
            while i < guard.active_keys.len() {
                let key = guard.active_keys[i];

                let mut popped: Option<(usize, SockAddr)> = None;
                let mut should_deactivate = false;

                {
                    let queue_opt = guard.get_queue_mut(key);

                    match queue_opt {
                        Some(queue) => {
                            if let Some(data) = queue.buffer.pop() {
                                let buf_idx = pending.len();
                                if buf_idx >= send_bufs.len() {
                                    send_bufs.push([0u8; MAX_PACKET_SIZE]);
                                }

                                send_bufs[buf_idx][..data.len()].copy_from_slice(data);
                                popped = Some((data.len(), queue.addr.clone()));

                                if queue.buffer.is_empty() {
                                    should_deactivate = true;
                                }
                            } else {
                                should_deactivate = true;
                            }
                        }
                        None => {
                            should_deactivate = true;
                        }
                    }
                }

                if let Some((len, addr)) = popped {
                    pending.push(PendingPacket { len, addr });
                }

                if should_deactivate {
                    guard.deactivate_active_key_at(i);
                } else {
                    i += 1;
                }
            }
        }

        for (i, pkt) in pending.iter().enumerate() {
            match socket.send_to(&send_bufs[i][..pkt.len], &pkt.addr) {
                Ok(_) => {
                    packets_sent.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    packets_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        let now = Instant::now();
        if next_tick > now {
            platform::precise_sleep_until(next_tick, &sleep_ctx);
        } else {
            next_tick = now;
        }
    }
}

// ---------------------------------------------------------------------------
// NAPI objects
// ---------------------------------------------------------------------------

#[napi(object)]
pub struct UdpQueueStats {
    pub packets_sent: i64,
    pub packets_dropped: i64,
}

#[napi(object)]
pub struct QueueInfo {
    pub queued_packets: u32,
    pub capacity_packets: u32,
}

// ---------------------------------------------------------------------------
// UdpQueueManager
// ---------------------------------------------------------------------------

#[napi]
pub struct UdpQueueManager {
    inner: Arc<Mutex<QueueManagerInner>>,
    socket: Arc<Socket>,
    running: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
    packets_dropped: Arc<AtomicU64>,
    default_buffer_duration_ms: u32,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl UdpQueueManager {
    fn shutdown(&mut self) {
        if self.running.swap(false, Ordering::AcqRel) {
            if let Some(handle) = self.thread_handle.take() {
                let _ = handle.join();
            }
        }

        if let Ok(mut guard) = self.inner.lock() {
            guard.active_keys.clear();
            guard.queues.clear();
        }
    }
}

impl Drop for UdpQueueManager {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[napi]
impl UdpQueueManager {
    #[napi(constructor)]
    pub fn new(buffer_duration_ms: Option<u32>) -> Result<Self> {
        let default_buffer_duration_ms = buffer_duration_ms
            .unwrap_or(DEFAULT_BUFFER_DURATION_MS)
            .max(20);

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| napi::Error::from_reason(format!("Failed to create UDP socket: {e}")))?;

        socket
            .set_nonblocking(true)
            .map_err(|e| napi::Error::from_reason(format!("Failed to set non-blocking: {e}")))?;

        let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        socket
            .bind(&SockAddr::from(bind_addr))
            .map_err(|e| napi::Error::from_reason(format!("Failed to bind socket: {e}")))?;

        let socket = Arc::new(socket);

        let inner = Arc::new(Mutex::new(QueueManagerInner::new()));
        let running = Arc::new(AtomicBool::new(true));
        let packets_sent = Arc::new(AtomicU64::new(0));
        let packets_dropped = Arc::new(AtomicU64::new(0));

        let thread_inner = Arc::clone(&inner);
        let thread_socket = Arc::clone(&socket);
        let thread_running = Arc::clone(&running);
        let thread_sent = Arc::clone(&packets_sent);
        let thread_dropped = Arc::clone(&packets_dropped);

        let thread_handle = thread::Builder::new()
            .name("udpqueue-sender".to_string())
            .spawn(move || {
                sender_thread(
                    thread_inner,
                    thread_socket,
                    thread_running,
                    thread_sent,
                    thread_dropped,
                );
            })
            .map_err(|e| napi::Error::from_reason(format!("Failed to spawn sender thread: {e}")))?;

        Ok(Self {
            inner,
            socket,
            running,
            packets_sent,
            packets_dropped,
            default_buffer_duration_ms,
            thread_handle: Some(thread_handle),
        })
    }

    /// Create a plain queue (backward compatible).
    /// Accepts fully-formed packets via pushPacket.
    #[napi]
    pub fn create_queue(
        &self,
        ip: String,
        port: u32,
        buffer_duration_ms: Option<u32>,
    ) -> Result<u32> {
        let addr: SocketAddr = format!("{ip}:{port}")
            .parse()
            .map_err(|e| napi::Error::from_reason(format!("Invalid address: {e}")))?;

        if !addr.is_ipv4() {
            return Err(napi::Error::from_reason(
                "Only IPv4 is supported by this socket configuration",
            ));
        }

        let capacity =
            queue_capacity_from_ms(buffer_duration_ms.unwrap_or(self.default_buffer_duration_ms));

        let queue = QueueInner {
            buffer: RingBuffer::new(capacity),
            addr: SockAddr::from(addr),
            active_index: None,
            voice_crypto: None,
        };

        let mut guard = self.inner.lock().unwrap();
        guard.insert_queue(queue)
    }

    /// Create a voice queue that handles RTP header construction + encryption
    /// natively. Use push_encrypted_frame to push raw Opus (or MLS-encrypted)
    /// frames with caller-supplied sequence/timestamp/nonce.
    ///
    /// `encryption_mode` must be one of:
    ///   - "aead_aes256_gcm_rtpsize"
    ///   - "aead_xchacha20_poly1305_rtpsize"
    ///
    /// `secret_key` must be exactly 32 bytes.
    #[napi]
    pub fn create_voice_queue(
        &self,
        ip: String,
        port: u32,
        ssrc: u32,
        encryption_mode: String,
        secret_key: Buffer,
        buffer_duration_ms: Option<u32>,
    ) -> Result<u32> {
        let addr: SocketAddr = format!("{ip}:{port}")
            .parse()
            .map_err(|e| napi::Error::from_reason(format!("Invalid address: {e}")))?;

        if !addr.is_ipv4() {
            return Err(napi::Error::from_reason(
                "Only IPv4 is supported by this socket configuration",
            ));
        }

        let enc_mode = EncryptionMode::from_str(&encryption_mode)
            .ok_or_else(|| napi::Error::from_reason(format!(
                "Unsupported encryption mode: '{encryption_mode}'. Use 'aead_aes256_gcm_rtpsize' or 'aead_xchacha20_poly1305_rtpsize'"
            )))?;

        if secret_key.len() != 32 {
            return Err(napi::Error::from_reason(
                "secret_key must be exactly 32 bytes",
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&secret_key);

        let capacity =
            queue_capacity_from_ms(buffer_duration_ms.unwrap_or(self.default_buffer_duration_ms));

        let voice_crypto = VoiceCryptoState {
            secret_key: key,
            ssrc,
            encryption_mode: enc_mode,
        };

        let queue = QueueInner {
            buffer: RingBuffer::new(capacity),
            addr: SockAddr::from(addr),
            active_index: None,
            voice_crypto: Some(voice_crypto),
        };

        let mut guard = self.inner.lock().unwrap();
        guard.insert_queue(queue)
    }

    /// Push a raw Opus (or MLS-encrypted) frame for native encryption + send.
    ///
    /// The caller (JS) owns sequence/timestamp/nonce — pass them explicitly
    /// so JS remains the single source of truth for counter state.
    ///
    /// The Rust code will:
    ///   1. Build the 12-byte RTP header with the given sequence/timestamp/ssrc
    ///   2. Encrypt the frame with the given nonce and the queue's key
    ///   3. Append the nonce trailer
    ///   4. Enqueue the fully-formed packet in the ring buffer
    ///
    /// Returns true if the frame was queued, false if the buffer is full.
    #[napi]
    pub fn push_encrypted_frame(
        &self,
        queue_key: u32,
        opus_frame: BufferSlice<'_>,
        sequence: u16,
        timestamp: u32,
        nonce: u32,
    ) -> Result<bool> {
        let mut packet_buf = [0u8; MAX_PACKET_SIZE];

        let mut guard = self.inner.lock().unwrap();

        let queue = guard
            .get_queue_mut(queue_key)
            .ok_or_else(|| napi::Error::from_reason("Queue not found"))?;

        let crypto = queue
            .voice_crypto
            .as_ref()
            .ok_or_else(|| napi::Error::from_reason(
                "Queue does not have voice encryption state. Use createVoiceQueue() instead of createQueue()."
            ))?;

        let packet_len = encrypt_and_pack(crypto, opus_frame.as_ref(), sequence, timestamp, nonce, &mut packet_buf)?;

        let was_empty = queue.buffer.is_empty();
        let pushed = queue.buffer.push(&packet_buf[..packet_len]);

        if pushed && was_empty {
            guard.activate_queue(queue_key);
        } else if !pushed {
            self.packets_dropped.fetch_add(1, Ordering::Relaxed);
        }

        Ok(pushed)
    }

    /// Update the encryption secret key for a voice queue.
    /// Discord rotates keys during session, so this must be callable
    /// without recreating the queue.
    #[napi]
    pub fn set_encryption_key(&self, queue_key: u32, secret_key: Buffer) -> Result<bool> {
        if secret_key.len() != 32 {
            return Err(napi::Error::from_reason(
                "secret_key must be exactly 32 bytes",
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&secret_key);

        let mut guard = self.inner.lock().unwrap();

        let queue = guard
            .get_queue_mut(queue_key)
            .ok_or_else(|| napi::Error::from_reason("Queue not found"))?;

        let crypto = queue
            .voice_crypto
            .as_mut()
            .ok_or_else(|| napi::Error::from_reason(
                "Queue does not have voice encryption state."
            ))?;

        crypto.secret_key = key;
        Ok(true)
    }

    /// Push a fully-formed packet buffer (backward compatible).
    /// Works with both plain queues and voice queues.
    #[napi]
    pub fn push_packet(&self, queue_key: u32, packet: BufferSlice<'_>) -> Result<bool> {
        let mut guard = self.inner.lock().unwrap();

        let queue = guard
            .get_queue_mut(queue_key)
            .ok_or_else(|| napi::Error::from_reason("Queue not found"))?;

        let was_empty = queue.buffer.is_empty();
        let pushed = queue.buffer.push(packet.as_ref());

        if pushed && was_empty {
            guard.activate_queue(queue_key);
        } else if !pushed {
            self.packets_dropped.fetch_add(1, Ordering::Relaxed);
        }

        Ok(pushed)
    }

    #[napi]
    pub fn delete_queue(&self, queue_key: u32) -> Result<bool> {
        let mut guard = self.inner.lock().unwrap();
        Ok(guard.remove_queue(queue_key))
    }

    #[napi]
    pub fn local_address(&self) -> Result<String> {
        let addr = self
            .socket
            .local_addr()
            .map_err(|e| napi::Error::from_reason(format!("Failed to get local address: {e}")))?;

        let socket_addr = addr
            .as_socket()
            .ok_or_else(|| napi::Error::from_reason("Local socket address unavailable"))?;

        Ok(socket_addr.to_string())
    }

    #[napi]
    pub fn close(&mut self) {
        self.shutdown();
    }

    #[napi]
    pub fn clear_queue(&self, queue_key: u32) -> Result<bool> {
        let mut guard = self.inner.lock().unwrap();

        let active_index = {
            let queue = guard
                .get_queue_mut(queue_key)
                .ok_or_else(|| napi::Error::from_reason("Queue not found"))?;

            queue.buffer.clear();
            queue.active_index
        };

        if let Some(pos) = active_index {
            guard.deactivate_active_key_at(pos);
        }

        Ok(true)
    }

    #[napi]
    pub fn stats(&self) -> UdpQueueStats {
        UdpQueueStats {
            packets_sent: self.packets_sent.load(Ordering::Relaxed) as i64,
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed) as i64,
        }
    }

    #[napi]
    pub fn queue_info(&self, queue_key: u32) -> Result<QueueInfo> {
        let guard = self.inner.lock().unwrap();

        let queue = guard
            .get_queue(queue_key)
            .ok_or_else(|| napi::Error::from_reason("Queue not found"))?;

        Ok(QueueInfo {
            queued_packets: queue.buffer.len() as u32,
            capacity_packets: queue.buffer.capacity as u32,
        })
    }

    #[napi]
    pub fn update_queue_target(&self, queue_key: u32, ip: String, port: u32) -> Result<bool> {
        let addr: SocketAddr = format!("{ip}:{port}")
            .parse()
            .map_err(|e| napi::Error::from_reason(format!("Invalid address: {e}")))?;

        if !addr.is_ipv4() {
            return Err(napi::Error::from_reason(
                "Only IPv4 is supported by this socket configuration",
            ));
        }

        let mut guard = self.inner.lock().unwrap();

        let queue = guard
            .get_queue_mut(queue_key)
            .ok_or_else(|| napi::Error::from_reason("Queue not found"))?;

        queue.addr = SockAddr::from(addr);
        Ok(true)
    }

    #[napi]
    pub fn send_now(&self, queue_key: u32, packet: BufferSlice<'_>) -> Result<bool> {
        let addr = {
            let guard = self.inner.lock().unwrap();
            let queue = guard
                .get_queue(queue_key)
                .ok_or_else(|| napi::Error::from_reason("Queue not found"))?;
            queue.addr.clone()
        };

        match self.socket.send_to(packet.as_ref(), &addr) {
            Ok(_) => {
                self.packets_sent.fetch_add(1, Ordering::Relaxed);
                Ok(true)
            }
            Err(_) => {
                self.packets_dropped.fetch_add(1, Ordering::Relaxed);
                Ok(false)
            }
        }
    }
}
