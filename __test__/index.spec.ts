import test from 'ava'
import { createRequire } from 'module'

const require = createRequire(import.meta.url)
const { UdpQueueManager } = require('../index.js')

test('UdpQueueManager can be created', (t) => {
  const qm = new UdpQueueManager(400)
  t.true(qm instanceof UdpQueueManager)
  qm.deleteQueue(0)
})

test('UdpQueueManager createQueue returns valid key', (t) => {
  const qm = new UdpQueueManager(400)
  const key = qm.createQueue('127.0.0.1', 9001, null)
  t.is(typeof key, 'number')
  t.true(key >= 0)
  qm.deleteQueue(key)
})

test('UdpQueueManager can push and delete queue', (t) => {
  const qm = new UdpQueueManager(400)
  const key = qm.createQueue('127.0.0.1', 9001, null)
  const pushed = qm.pushPacket(key, new Uint8Array([1, 2, 3]))
  t.true(pushed)
  qm.deleteQueue(key)
})
