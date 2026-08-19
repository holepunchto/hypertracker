const test = require('brittle')
const crypto = require('hypercore-crypto')
const HyperDHT = require('hyperdht')
const setupTestnet = require('hyperdht/testnet')
const promClient = require('prom-client')

const { HyperTracker, HyperTrackerClient } = require('.')

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
  const server = new HyperTracker(storage, { dht: serverDht })
  t.teardown(() => server.close(), { order: 3000 })
  await server.ready()

  const subscriber = new HyperTrackerClient(server.publicKey, { dht: subscriberDht })
  t.teardown(() => subscriber.close(), { order: 2000 })
  const announcer = new HyperTrackerClient(server.publicKey, { dht: announcerDht })
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
  const server = new HyperTracker(storage, { dht: serverDht })
  t.teardown(() => server.close(), { order: 3000 })
  await server.ready()

  const announcer = new HyperTrackerClient(server.publicKey, { dht: announcerDht })
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
  const server = new HyperTracker(storage, { dht: serverDht })
  t.teardown(() => server.close(), { order: 3000 })
  await server.ready()

  const subscriber = new HyperTrackerClient(server.publicKey, { dht: subscriberDht })
  t.teardown(() => subscriber.close(), { order: 2000 })
  const announcer = new HyperTrackerClient(server.publicKey, { dht: announcerDht })
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
  const server = new HyperTracker(storage, { dht: serverDht })
  t.teardown(() => server.close(), { order: 3000 })
  await server.ready()

  const announcer = new HyperTrackerClient(server.publicKey, { dht: announcerDht })
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

test('rejects announce bumps too far in the future', async (t) => {
  const testnet = await setupTestnet()
  const { bootstrap } = testnet
  t.teardown(() => testnet.destroy(), { order: 5000 })

  const serverDht = new HyperDHT({ bootstrap })
  t.teardown(() => serverDht.destroy(), { order: 4000 })
  const announcerDht = new HyperDHT({ bootstrap })
  t.teardown(() => announcerDht.destroy(), { order: 4000 })

  const storage = await t.tmp()
  const server = new HyperTracker(storage, { dht: serverDht })
  t.teardown(() => server.close(), { order: 3000 })
  await server.ready()

  const announcer = new HyperTrackerClient(server.publicKey, { dht: announcerDht })
  t.teardown(() => announcer.close(), { order: 2000 })
  const keyPair = crypto.keyPair()

  // TIME_SLACK is 60s; a bump far beyond that must be rejected.
  await announcer.announce(keyPair, { bump: Date.now() + 120_000 })
  await waitFor(() => server.stats.onannounceCount === 1)

  t.is(server.stats.announces, 0, 'future bump is not accepted')
  t.alike(await server.lookup(keyPair.publicKey), null, 'no record stored for future bump')

  // A bump within the slack window is still accepted.
  const withinSlack = Date.now() + 30_000
  await announcer.announce(keyPair, { bump: withinSlack })
  const record = await waitForRecord(server, keyPair.publicKey)

  t.is(server.stats.announces, 1, 'bump within slack is accepted')
  t.is(record.bumped, withinSlack, 'stores the within-slack bump')
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
  const server = new HyperTracker(storage, { dht: serverDht })
  t.teardown(() => server.close(), { order: 3000 })
  await server.ready()

  const announcer = new HyperTrackerClient(server.publicKey, { dht: announcerDht })
  t.teardown(() => announcer.close(), { order: 2000 })
  const keyPair = crypto.keyPair()

  const bump = Date.now()
  await announcer.announce(keyPair, { bump })
  await waitForRecord(server, keyPair.publicKey)

  const subscriber = new HyperTrackerClient(server.publicKey, { dht: subscriberDht })
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
  const server = new HyperTracker(storage, { dht: serverDht })
  t.teardown(() => server.close(), { order: 3000 })
  await server.ready()

  t.alike(
    server.stats,
    {
      streamsAdded: 0,
      streamsEnded: 0,
      subscriptionsAdded: 0,
      subscriptionsRemoved: 0,
      announces: 0,
      announcesSent: 0,
      onsubscribeCount: 0,
      onunsubscribeCount: 0,
      onannounceCount: 0
    },
    'stats start at zero'
  )

  const subscriber = new HyperTrackerClient(server.publicKey, { dht: subscriberDht })
  t.teardown(() => subscriber.close(), { order: 2000 })
  const announcer = new HyperTrackerClient(server.publicKey, { dht: announcerDht })
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

  t.is(server.stats.streamsAdded, 2, 'two streams added')
  t.is(server.stats.streamsEnded, 0, 'no streams ended yet')
  t.is(server.stats.subscriptionsAdded, 1, 'one subscription added')
  t.is(server.stats.subscriptionsRemoved, 0, 'no subscriptions removed yet')
  t.is(server.stats.announces, 1, 'one successful announce')
  t.is(server.stats.announcesSent, 1, 'one bump sent to subscriber')
  t.is(server.stats.onsubscribeCount, 1, 'one subscribe message')
  t.is(server.stats.onannounceCount, 1, 'one announce message')
  t.is(server.stats.onunsubscribeCount, 0, 'no unsubscribe yet')

  subscriber.unsubscribe(keyPair.publicKey)
  await waitFor(() => server.stats.onunsubscribeCount === 1)

  t.is(server.stats.onunsubscribeCount, 1, 'one unsubscribe message')
  t.is(server.stats.subscriptionsRemoved, 1, 'one subscription removed')

  await subscriber.close()
  await waitFor(() => server.stats.streamsEnded === 1)

  t.is(server.stats.streamsAdded, 2, 'stream add count is cumulative')
  t.is(server.stats.streamsEnded, 1, 'subscriber stream ended')
  t.is(server.stats.subscriptionsAdded, 1, 'subscription add count is cumulative')
  t.is(server.stats.subscriptionsRemoved, 1, 'subscription remove count is cumulative')
})

test('metrics', async (t) => {
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
  const server = new HyperTracker(storage, { dht: serverDht })
  t.teardown(() => server.close(), { order: 3000 })
  await server.ready()

  promClient.register.clear()
  server.registerMetrics(promClient)
  t.teardown(() => promClient.register.clear())

  const subscriber = new HyperTrackerClient(server.publicKey, { dht: subscriberDht })
  t.teardown(() => subscriber.close(), { order: 2000 })
  const announcer = new HyperTrackerClient(server.publicKey, { dht: announcerDht })
  t.teardown(() => announcer.close(), { order: 2000 })

  const keyPair = crypto.keyPair()

  subscriber.subscribe(keyPair.publicKey)
  await announcer.announce(keyPair)
  await waitFor(() => server.stats.announces === 1)

  subscriber.unsubscribe(keyPair.publicKey)
  await waitFor(() => server.stats.onunsubscribeCount === 1)

  await subscriber.close()
  await waitFor(() => server.stats.streamsEnded === 1)

  const metrics = await promClient.register.metrics()

  t.ok(metrics.includes('hypertracker_streams_added 2'), 'streams added metric')
  t.ok(metrics.includes('hypertracker_streams_ended 1'), 'streams ended metric')
  t.ok(metrics.includes('hypertracker_subscriptions_added 1'), 'subscriptions added metric')
  t.ok(metrics.includes('hypertracker_subscriptions_removed 1'), 'subscriptions removed metric')
  t.ok(metrics.includes('hypertracker_announces 1'), 'announces metric')
  t.ok(metrics.includes('hypertracker_announces_sent 1'), 'announces sent metric')
  t.ok(metrics.includes('hypertracker_onsubscribe_count 1'), 'onsubscribe count metric')
  t.ok(metrics.includes('hypertracker_onunsubscribe_count 1'), 'onunsubscribe count metric')
  t.ok(metrics.includes('hypertracker_onannounce_count 1'), 'onannounce count metric')
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
