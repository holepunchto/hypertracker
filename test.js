const test = require('brittle')
const crypto = require('hypercore-crypto')
const HyperDHT = require('hyperdht')
const setupTestnet = require('hyperdht/testnet')

const { HyperDiscovery, HyperDiscoveryClient } = require('.')

test('subscriber receives event from announcer', async (t) => {
  const testnet = await setupTestnet()
  const { bootstrap } = testnet
  t.teardown(() => testnet.destroy(), { order: 5000 })

  const serverDht = new HyperDHT({ bootstrap })
  t.teardown(() => serverDht.destroy(), { order: 4000 })
  const subscriberDht = new HyperDHT({ bootstrap })
  t.teardown(() => subscriberDht.destroy(), { order: 4000 })
  const announcerDht = new HyperDHT({ bootstrap })
  t.teardown(() => announcerDht.destroy(), { order: 4000 })

  const storage = await t.tmp()
  const server = new HyperDiscovery(storage, { dht: serverDht })
  t.teardown(() => server.close(), { order: 3000 })
  await server.ready()

  const subscriber = new HyperDiscoveryClient(server.publicKey, { dht: subscriberDht })
  t.teardown(() => subscriber.close(), { order: 2000 })
  const announcer = new HyperDiscoveryClient(server.publicKey, { dht: announcerDht })
  t.teardown(() => announcer.close(), { order: 2000 })

  const keyPair = crypto.keyPair()

  const announced = t.test('announce event')
  announced.plan(1)

  subscriber.on('announce', (ann) => {
    announced.alike(ann.publicKey, keyPair.publicKey, 'announced public key matches')
  })

  subscriber.subscribe(keyPair.publicKey)
  await announcer.announce(keyPair)

  await announced
})

test('lookup returns the latest announce', async (t) => {
  const testnet = await setupTestnet()
  const { bootstrap } = testnet
  t.teardown(() => testnet.destroy(), { order: 5000 })

  const serverDht = new HyperDHT({ bootstrap })
  t.teardown(() => serverDht.destroy(), { order: 4000 })
  const announcerDht = new HyperDHT({ bootstrap })
  t.teardown(() => announcerDht.destroy(), { order: 4000 })

  const storage = await t.tmp()
  const server = new HyperDiscovery(storage, { dht: serverDht })
  t.teardown(() => server.close(), { order: 3000 })
  await server.ready()

  const announcer = new HyperDiscoveryClient(server.publicKey, { dht: announcerDht })
  t.teardown(() => announcer.close(), { order: 2000 })
  const keyPair = crypto.keyPair()

  t.alike(await server.lookup(keyPair.publicKey), null, 'no record')

  const bump = Date.now()
  await announcer.announce(keyPair, { bump })

  const record = await waitForRecord(server, keyPair.publicKey)
  t.ok(record, 'record exists after announce')
  t.is(record.bumped, bump, 'stores the bump timestamp')

  const bump2 = bump + 10_000
  await announcer.announce(keyPair, { bump: bump2 })
  await new Promise((resolve) => setTimeout(resolve, 800))

  const updated = await server.lookup(keyPair.publicKey)
  t.is(updated.bumped, bump2, 'lookup reflects a newer announce')
})

test('unsubscribe stops future announces', async (t) => {
  const testnet = await setupTestnet()
  const { bootstrap } = testnet
  t.teardown(() => testnet.destroy(), { order: 5000 })

  const serverDht = new HyperDHT({ bootstrap })
  t.teardown(() => serverDht.destroy(), { order: 4000 })
  const subscriberDht = new HyperDHT({ bootstrap })
  t.teardown(() => subscriberDht.destroy(), { order: 4000 })
  const announcerDht = new HyperDHT({ bootstrap })
  t.teardown(() => announcerDht.destroy(), { order: 4000 })

  const storage = await t.tmp()
  const server = new HyperDiscovery(storage, { dht: serverDht })
  t.teardown(() => server.close(), { order: 3000 })
  await server.ready()

  const subscriber = new HyperDiscoveryClient(server.publicKey, { dht: subscriberDht })
  t.teardown(() => subscriber.close(), { order: 2000 })
  const announcer = new HyperDiscoveryClient(server.publicKey, { dht: announcerDht })
  t.teardown(() => announcer.close(), { order: 2000 })

  const keyPair = crypto.keyPair()

  subscriber.on('announce', () => t.fail('should not receive announce after unsubscribing'))

  subscriber.subscribe(keyPair.publicKey)
  subscriber.unsubscribe(keyPair.publicKey)

  await announcer.announce(keyPair)

  await new Promise((resolve) => setTimeout(resolve, 1500))
  t.pass('no announce received')
})

test('stale announce does not overwrite a newer record', async (t) => {
  const testnet = await setupTestnet()
  const { bootstrap } = testnet
  t.teardown(() => testnet.destroy(), { order: 5000 })

  const serverDht = new HyperDHT({ bootstrap })
  t.teardown(() => serverDht.destroy(), { order: 4000 })
  const announcerDht = new HyperDHT({ bootstrap })
  t.teardown(() => announcerDht.destroy(), { order: 4000 })

  const storage = await t.tmp()
  const server = new HyperDiscovery(storage, { dht: serverDht })
  t.teardown(() => server.close(), { order: 3000 })
  await server.ready()

  const announcer = new HyperDiscoveryClient(server.publicKey, { dht: announcerDht })
  t.teardown(() => announcer.close(), { order: 2000 })
  const keyPair = crypto.keyPair()

  const bump = Date.now()
  await announcer.announce(keyPair, { bump })

  const record = await waitForRecord(server, keyPair.publicKey)
  t.ok(record, 'record exists after first announce')

  await announcer.announce(keyPair, { bump: bump - 10_000 })
  await new Promise((resolve) => setTimeout(resolve, 800))

  const stale = await server.lookup(keyPair.publicKey)
  t.is(stale.bumped, record.bumped, 'bump is unchanged by an older announce')
  t.is(stale.updated, record.updated, 'record is untouched by an older announce')
})

test('subscribing after an announce delivers the current record', async (t) => {
  const testnet = await setupTestnet()
  const { bootstrap } = testnet
  t.teardown(() => testnet.destroy(), { order: 5000 })

  const serverDht = new HyperDHT({ bootstrap })
  t.teardown(() => serverDht.destroy(), { order: 4000 })
  const subscriberDht = new HyperDHT({ bootstrap })
  t.teardown(() => subscriberDht.destroy(), { order: 4000 })
  const announcerDht = new HyperDHT({ bootstrap })
  t.teardown(() => announcerDht.destroy(), { order: 4000 })

  const storage = await t.tmp()
  const server = new HyperDiscovery(storage, { dht: serverDht })
  t.teardown(() => server.close(), { order: 3000 })
  await server.ready()

  const announcer = new HyperDiscoveryClient(server.publicKey, { dht: announcerDht })
  t.teardown(() => announcer.close(), { order: 2000 })
  const keyPair = crypto.keyPair()

  const bump = Date.now()
  await announcer.announce(keyPair, { bump })
  await waitForRecord(server, keyPair.publicKey)

  const subscriber = new HyperDiscoveryClient(server.publicKey, { dht: subscriberDht })
  t.teardown(() => subscriber.close(), { order: 2000 })

  const caughtUp = t.test('catch-up announce')
  caughtUp.plan(1)

  subscriber.on('announce', (ann) => {
    caughtUp.is(ann.bumped, bump, 'delivers the already-stored bump on subscribe')
  })

  subscriber.subscribe(keyPair.publicKey)

  await caughtUp
})

async function waitForRecord(server, publicKey, timeout = 5000) {
  const start = Date.now()
  while (Date.now() - start < timeout) {
    const record = await server.lookup(publicKey)
    if (record) return record
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  return null
}
