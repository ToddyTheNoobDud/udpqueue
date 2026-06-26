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
  const key = qm.createQueue(400)
  t.is(typeof key, 'number')
  t.true(key >= 0)
  qm.deleteQueue(key)
})

test('UdpQueueManager can push and delete queue', (t) => {
  const qm = new UdpQueueManager(400)
  const key = qm.createQueue(400)
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

  qm.resetPacing(key)
  const packet = qm.drainQueue(key, Number(process.hrtime.bigint()))

  t.true(packet instanceof Buffer)
  t.deepEqual(packet, Buffer.from([1, 2, 3]))
  qm.deleteQueue(key)
})

test('UdpQueueManager drainAll returns packets one per call', (t) => {
  const qm = new UdpQueueManager(400)
  const key = qm.createQueue(400)

  qm.pushPacket(key, new Uint8Array([1]))
  qm.pushPacket(key, new Uint8Array([2]))

  qm.resetPacing(key)
  const nowNs = Number(process.hrtime.bigint())

  // drainAll returns one per queue per call due to pacing
  const items1 = qm.drainAll(nowNs)
  t.is(items1.length, 1)
  t.is(items1[0].queueKey, key)
  t.deepEqual(items1[0].data, Buffer.from([1]))

  // Second call gets the next packet (pacing elapsed)
  const items2 = qm.drainAll(nowNs + 20_000_000) // +20ms in ns
  t.is(items2.length, 1)
  t.deepEqual(items2[0].data, Buffer.from([2]))

  qm.deleteQueue(key)
})

test('UdpQueueManager stats tracks drops', (t) => {
  const qm = new UdpQueueManager(400)
  const key = qm.createQueue(20) // 1 packet capacity

  qm.pushPacket(key, new Uint8Array([1]))
  const dropped = qm.pushPacket(key, new Uint8Array([2])) // should fail

  t.false(dropped)

  const stats = qm.stats()
  // napi-rs converts snake_case to camelCase
  t.is(stats.packetsQueued, 1)
  t.is(stats.packetsDropped, 1)
  qm.deleteQueue(key)
})

test('UdpQueueManager queueInfo reports correctly', (t) => {
  const qm = new UdpQueueManager(400)
  const key = qm.createQueue(400)

  const info = qm.queueInfo(key)
  // napi-rs converts snake_case to camelCase
  t.is(info.queuedPackets, 0)
  t.is(info.capacityPackets, 20) // 400ms / 20ms = 20

  qm.pushPacket(key, new Uint8Array([1]))
  const info2 = qm.queueInfo(key)
  t.is(info2.queuedPackets, 1)

  qm.deleteQueue(key)
})
