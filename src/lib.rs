use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const FRAME_DURATION_NS: u64 = 20_000_000; // 20ms
const MAX_PACKET_SIZE: usize = 4096;
const DEFAULT_BUFFER_DURATION_MS: u32 = 400;
const PREALLOCATED_QUEUES: usize = 64;

fn queue_capacity_from_ms(buffer_duration_ms: u32) -> usize {
  ((buffer_duration_ms as usize) / 20).max(1)
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
  next_send_time_ns: u64,
}

struct QueueManagerInner {
  queues: Vec<Option<QueueInner>>,
}

impl QueueManagerInner {
  fn new() -> Self {
    Self {
      queues: Vec::with_capacity(PREALLOCATED_QUEUES),
    }
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

  fn remove_queue(&mut self, key: u32) -> bool {
    let idx = key as usize;
    if idx >= self.queues.len() || self.queues[idx].is_none() {
      return false;
    }
    self.queues[idx] = None;
    true
  }
}

// ---------------------------------------------------------------------------
// NAPI objects
// ---------------------------------------------------------------------------

#[napi(object)]
pub struct UdpQueueStats {
  pub packets_queued: i64,
  pub packets_dropped: i64,
}

#[napi(object)]
pub struct QueueInfo {
  pub queued_packets: u32,
  pub capacity_packets: u32,
}

#[napi(object)]
pub struct DrainItem {
  pub queue_key: u32,
  pub data: Buffer,
}

// ---------------------------------------------------------------------------
// UdpQueueManager
// ---------------------------------------------------------------------------

#[napi]
pub struct UdpQueueManager {
  inner: Arc<Mutex<QueueManagerInner>>,
  packets_queued: Arc<AtomicU64>,
  packets_dropped: Arc<AtomicU64>,
  default_buffer_duration_ms: u32,
}

impl Drop for UdpQueueManager {
  fn drop(&mut self) {}
}

#[napi]
impl UdpQueueManager {
  #[napi(constructor)]
  pub fn new(buffer_duration_ms: Option<u32>) -> Result<Self> {
    let default_buffer_duration_ms = buffer_duration_ms
      .unwrap_or(DEFAULT_BUFFER_DURATION_MS)
      .max(20);

    Ok(Self {
      inner: Arc::new(Mutex::new(QueueManagerInner::new())),
      packets_queued: Arc::new(AtomicU64::new(0)),
      packets_dropped: Arc::new(AtomicU64::new(0)),
      default_buffer_duration_ms,
    })
  }

  #[napi]
  pub fn create_queue(&self, buffer_duration_ms: Option<u32>) -> Result<u32> {
    let capacity =
      queue_capacity_from_ms(buffer_duration_ms.unwrap_or(self.default_buffer_duration_ms));

    let queue = QueueInner {
      buffer: RingBuffer::new(capacity),
      next_send_time_ns: 0,
    };

    let mut guard = self.inner.lock().unwrap();
    guard.insert_queue(queue)
  }

  #[napi]
  pub fn push_packet(&self, queue_key: u32, packet: BufferSlice<'_>) -> Result<bool> {
    let mut guard = self.inner.lock().unwrap();

    let queue = guard
      .get_queue_mut(queue_key)
      .ok_or_else(|| napi::Error::from_reason("Queue not found"))?;

    let pushed = queue.buffer.push(packet.as_ref());

    if pushed {
      self.packets_queued.fetch_add(1, Ordering::Relaxed);
    } else {
      self.packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    Ok(pushed)
  }

  #[napi]
  pub fn drain_queue(&self, queue_key: u32, now_ns: i64) -> Result<Option<Buffer>> {
    let mut guard = self.inner.lock().unwrap();

    let queue = guard
      .get_queue_mut(queue_key)
      .ok_or_else(|| napi::Error::from_reason("Queue not found"))?;

    if queue.buffer.is_empty() {
      return Ok(None);
    }

    let now = now_ns as u64;

    // Initialize next_send_time on first packet
    if queue.next_send_time_ns == 0 {
      queue.next_send_time_ns = now;
    }

    if queue.next_send_time_ns > now {
      return Ok(None);
    }

    let data = queue.buffer.pop().unwrap(); // safe: checked is_empty above
    queue.next_send_time_ns += FRAME_DURATION_NS;

    Ok(Some(Buffer::from(data.to_vec())))
  }

  #[napi]
  pub fn drain_all(&self, now_ns: i64) -> Result<Vec<DrainItem>> {
    let mut guard = self.inner.lock().unwrap();
    let now = now_ns as u64;
    let mut items = Vec::with_capacity(PREALLOCATED_QUEUES);

    for (idx, queue_opt) in guard.queues.iter_mut().enumerate() {
      let queue = match queue_opt {
        Some(q) => q,
        None => continue,
      };

      if queue.buffer.is_empty() {
        continue;
      }

      if queue.next_send_time_ns == 0 {
        queue.next_send_time_ns = now;
      }

      while queue.next_send_time_ns <= now {
        if let Some(data) = queue.buffer.pop() {
          items.push(DrainItem {
            queue_key: idx as u32,
            data: Buffer::from(data.to_vec()),
          });
          queue.next_send_time_ns += FRAME_DURATION_NS;
        } else {
          break;
        }
      }
    }

    Ok(items)
  }

  #[napi]
  pub fn reset_pacing(&self, queue_key: u32) -> Result<()> {
    let mut guard = self.inner.lock().unwrap();
    let queue = guard
      .get_queue_mut(queue_key)
      .ok_or_else(|| napi::Error::from_reason("Queue not found"))?;
    queue.next_send_time_ns = 0;
    Ok(())
  }

  #[napi]
  pub fn delete_queue(&self, queue_key: u32) -> Result<bool> {
    let mut guard = self.inner.lock().unwrap();
    Ok(guard.remove_queue(queue_key))
  }

  #[napi]
  pub fn clear_queue(&self, queue_key: u32) -> Result<bool> {
    let mut guard = self.inner.lock().unwrap();
    let queue = guard
      .get_queue_mut(queue_key)
      .ok_or_else(|| napi::Error::from_reason("Queue not found"))?;
    queue.buffer.clear();
    queue.next_send_time_ns = 0;
    Ok(true)
  }

  #[napi]
  pub fn stats(&self) -> UdpQueueStats {
    UdpQueueStats {
      packets_queued: self.packets_queued.load(Ordering::Relaxed) as i64,
      packets_dropped: self.packets_dropped.load(Ordering::Relaxed) as i64,
    }
  }

  #[napi]
  pub fn queue_info(&self, queue_key: u32) -> Result<QueueInfo> {
    let mut guard = self.inner.lock().unwrap();
    let queue = guard
      .get_queue_mut(queue_key)
      .ok_or_else(|| napi::Error::from_reason("Queue not found"))?;

    Ok(QueueInfo {
      queued_packets: queue.buffer.len() as u32,
      capacity_packets: queue.buffer.capacity as u32,
    })
  }
}
