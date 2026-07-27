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
  let receivedCount = 0

  const firstAnnounce = t.test('first announce while subscribed')
  firstAnnounce.plan(1)

  subscriber.on('announce', () => {
    receivedCount++
    if (receivedCount === 1) firstAnnounce.pass('subscriber receives an announce while subscribed')
  })

  subscriber.subscribe(keyPair.publicKey)
  await announcer.announce(keyPair, { bump: Date.now() })

  await firstAnnounce

  subscriber.unsubscribe(keyPair.publicKey)
  await announcer.announce(keyPair, { bump: Date.now() + 10_000 })

  await new Promise((resolve) => setTimeout(resolve, 1500))
  t.is(receivedCount, 1, 'no further announce received after unsubscribing')
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

  const newerBump = bump + 10_000
  await announcer.announce(keyPair, { bump: newerBump })
  await new Promise((resolve) => setTimeout(resolve, 800))

  const updated = await server.lookup(keyPair.publicKey)
  t.is(updated.bumped, newerBump, 'a genuinely newer announce still updates the record')
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

test('stats', async (t) => {
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

  t.alike(
    server.stats,
    {
      connections: 0,
      subscriptions: 0,
      announces: 0,
      sentAnnounces: 0,
      onsubscribeCount: 0,
      onunsubscribeCount: 0,
      onannounceCount: 0
    },
    'stats start at zero'
  )

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

  t.is(server.stats.streamsAdded, 2, 'two client connections')
  t.is(server.stats.subscriptions, 1, 'one active subscription')
  t.is(server.stats.announces, 1, 'one successful announce')
  t.is(server.stats.sentAnnounces, 1, 'one bump sent to subscriber')
  t.is(server.stats.onsubscribeCount, 1, 'one subscribe message')
  t.is(server.stats.onannounceCount, 1, 'one announce message')
  t.is(server.stats.onunsubscribeCount, 0, 'no unsubscribe yet')

  subscriber.unsubscribe(keyPair.publicKey)
  await waitFor(() => server.stats.onunsubscribeCount === 1)

  t.is(server.stats.onunsubscribeCount, 1, 'one unsubscribe message')
  t.is(server.stats.subscriptions, 0, 'subscription removed')

  await subscriber.close()
  await waitFor(() => server.stats.streamsAdded === 1)

  t.is(server.stats.streamsAdded, 1, 'subscriber connection closed')
  t.is(server.stats.subscriptions, 0, 'subscriptions stay at zero after disconnect')
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

async function waitFor(condition, timeout = 5000) {
  const start = Date.now()
  while (Date.now() - start < timeout) {
    if (condition()) return
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error('timed out waiting for condition')
}
