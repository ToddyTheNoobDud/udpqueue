import test from 'ava'
import { createRequire } from 'module'

const require = createRequire(import.meta.url)
const { UdpQueueManager } = require('../index.js')

test('UdpQueueManager can be created', (t) => {
  const qm = new UdpQueueManager(400)
  t.true(qm instanceof UdpQueueManager)
})

test('UdpQueueManager createQueue returns valid key', (t) => {
  const qm = new UdpQueueManager(400)
  const key = qm.createQueue(400)  // only buffer_duration_ms
  t.is(typeof key, 'number')
  t.true(key >= 0)
  qm.deleteQueue(key)
})

test('UdpQueueManager can push and delete queue', (t) => {
  const qm = new UdpQueueManager(400)
  const key = qm.createQueue(400)  // only buffer_duration_ms
  const pushed = qm.pushPacket(key, new Uint8Array([1, 2, 3]))
  t.true(pushed)
  qm.deleteQueue(key)
})

test('UdpQueueManager drainQueue returns null when empty', (t) => {
  const qm = new UdpQueueManager(400)
  const key = qm.createQueue(400)
  const packet = qm.drainQueue(key, Number(process.hrtime.bigint()))
  t.is(packet, null)
  qm.deleteQueue(key)
})

test('UdpQueueManager drainQueue returns packet after push', (t) => {
  const qm = new UdpQueueManager(400)
  const key = qm.createQueue(400)
  const data = new Uint8Array([1, 2, 3])

  qm.pushPacket(key, data)

  // First call might return null if pacing hasn't elapsed
  // Reset pacing and drain
  qm.resetPacing(key)
  const packet = qm.drainQueue(key, Number(process.hrtime.bigint()))

  t.true(packet instanceof Buffer)
  t.deepEqual(packet, Buffer.from([1, 2, 3]))
  qm.deleteQueue(key)
})

test('UdpQueueManager drainAll returns packets', (t) => {
  const qm = new UdpQueueManager(400)
  const key = qm.createQueue(400)

  qm.pushPacket(key, new Uint8Array([1]))
  qm.pushPacket(key, new Uint8Array([2]))

  qm.resetPacing(key)
  const items = qm.drainAll(Number(process.hrtime.bigint()))

  t.true(Array.isArray(items))
  t.is(items.length, 2)
  t.is(items[0].queue_key, key)
  t.deepEqual(items[0].data, Buffer.from([1]))
  qm.deleteQueue(key)
})

test('UdpQueueManager stats tracks drops', (t) => {
  const qm = new UdpQueueManager(400)
  const key = qm.createQueue(20) // 1 packet capacity

  qm.pushPacket(key, new Uint8Array([1]))
  const dropped = qm.pushPacket(key, new Uint8Array([2])) // should fail

  t.false(dropped)

  const stats = qm.stats()
  t.is(stats.packets_queued, 1)
  t.is(stats.packets_dropped, 1)
  qm.deleteQueue(key)
})

test('UdpQueueManager queueInfo reports correctly', (t) => {
  const qm = new UdpQueueManager(400)
  const key = qm.createQueue(400)

  const info = qm.queueInfo(key)
  t.is(info.queued_packets, 0)
  t.is(info.capacity_packets, 20) // 400ms / 20ms = 20

  qm.pushPacket(key, new Uint8Array([1]))
  const info2 = qm.queueInfo(key)
  t.is(info2.queued_packets, 1)

  qm.deleteQueue(key)
})
