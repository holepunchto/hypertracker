const test = require('brittle')
const crypto = require('hypercore-crypto')
const HyperDHT = require('hyperdht')
const setupTestnet = require('hyperdht/testnet')

const { HyperDiscovery, HyperDiscoveryClient } = require('.')

test('subscriber receives event from announcer', async (t) => {
  const { subscriber, announcer, keyPair } = await setup(t)

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
  const { server, announcer, keyPair } = await setup(t)

  t.alike(await server.lookup(keyPair.publicKey), null, 'no record')

  const bump = Date.now()
  await announcer.announce(keyPair, { bump })

  const record = await waitForRecord(server, keyPair.publicKey)
  t.ok(record, 'record exists after announce')
  t.is(record.bumped, bump, 'stores the bump timestamp')

  const bump2 = bump + 10_000
  await announcer.announce(keyPair, { bump: bump2 })
  await delay(800)

  const updated = await server.lookup(keyPair.publicKey)
  t.is(updated.bumped, bump2, 'lookup reflects a newer announce')
})

test('unsubscribe stops future announces', async (t) => {
  const { subscriber, announcer, keyPair } = await setup(t)
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

  await delay(1500)
  t.is(receivedCount, 1, 'no further announce received after unsubscribing')
})

test('stale announce does not overwrite a newer record', async (t) => {
  const { server, announcer, keyPair } = await setup(t)

  const bump = Date.now()
  await announcer.announce(keyPair, { bump })

  const record = await waitForRecord(server, keyPair.publicKey)
  t.ok(record, 'record exists after first announce')

  await announcer.announce(keyPair, { bump: bump - 10_000 })
  await delay(800)

  const stale = await server.lookup(keyPair.publicKey)
  t.is(stale.bumped, record.bumped, 'bump is unchanged by an older announce')
  t.is(stale.updated, record.updated, 'record is untouched by an older announce')

  const newerBump = bump + 10_000
  await announcer.announce(keyPair, { bump: newerBump })
  await delay(800)

  const updated = await server.lookup(keyPair.publicKey)
  t.is(updated.bumped, newerBump, 'a genuinely newer announce still updates the record')
})

test('subscribing after an announce delivers the current record', async (t) => {
  const { server, subscriber, announcer, keyPair } = await setup(t)

  const bump = Date.now()
  await announcer.announce(keyPair, { bump })
  await waitForRecord(server, keyPair.publicKey)

  const caughtUp = t.test('catch-up announce')
  caughtUp.plan(1)

  subscriber.on('announce', (ann) => {
    caughtUp.is(ann.bumped, bump, 'delivers the already-stored bump on subscribe')
  })

  subscriber.subscribe(keyPair.publicKey)

  await caughtUp
})

test('since skips catch-up for older bumps', async (t) => {
  const { server, subscriber, announcer, keyPair } = await setup(t)

  const bump = Date.now()
  await announcer.announce(keyPair, { bump })
  await waitForRecord(server, keyPair.publicKey)

  const received = []
  subscriber.on('announce', (ann) => received.push(ann.bumped))

  subscriber.subscribe(keyPair.publicKey, { since: bump + 1 })
  await delay(500)
  t.alike(received, [], 'no catch-up when stored bump is older than since')

  const newerBump = bump + 10_000
  const newer = t.test('newer announce')
  newer.plan(1)
  subscriber.on('announce', (ann) => {
    if (ann.bumped === newerBump) {
      newer.is(ann.bumped, newerBump, 'still receives announces at or after since')
    }
  })
  await announcer.announce(keyPair, { bump: newerBump })
  await newer
})

test('resubscribes after server restart', async (t) => {
  t.timeout(60_000)

  const { bootstrap, storage, server, serverDht, subscriber, announcer, keyPair } = await setup(t)
  const publicKey = Buffer.from(server.publicKey)

  const connected = t.test('initial connect')
  connected.plan(2)
  subscriber.once('connect', () => connected.pass('subscriber connected'))
  announcer.once('connect', () => connected.pass('announcer connected'))
  subscriber.connect()
  announcer.connect()
  await connected

  const firstAnnounce = t.test('announce before restart')
  firstAnnounce.plan(1)
  subscriber.once('announce', (ann) => {
    firstAnnounce.alike(ann.publicKey, keyPair.publicKey, 'receives announce before restart')
  })
  subscriber.subscribe(keyPair.publicKey)
  await announcer.announce(keyPair, { bump: Date.now() })
  await firstAnnounce

  const reconnected = t.test('reconnect after restart')
  reconnected.plan(2)
  subscriber.once('connect', () => reconnected.pass('subscriber reconnected'))
  announcer.once('connect', () => reconnected.pass('announcer reconnected'))

  await server.close()
  await serverDht.destroy()

  const serverDht2 = new HyperDHT({ bootstrap })
  t.teardown(() => serverDht2.destroy(), { order: 4000 })
  const server2 = new HyperDiscovery(storage, { dht: serverDht2 })
  t.teardown(() => server2.close(), { order: 3000 })
  await server2.ready()
  t.alike(server2.publicKey, publicKey, 'restarted server keeps the same public key')

  await reconnected

  const bump = Date.now() + 10_000
  const secondAnnounce = t.test('announce after resubscribe')
  secondAnnounce.plan(1)
  subscriber.on('announce', (ann) => {
    if (ann.bumped === bump) {
      secondAnnounce.alike(
        ann.publicKey,
        keyPair.publicKey,
        'receives announce without calling subscribe again'
      )
    }
  })
  await announcer.announce(keyPair, { bump })
  await secondAnnounce
})

async function setup(t) {
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

  return { bootstrap, storage, serverDht, subscriberDht, announcerDht, server, subscriber, announcer, keyPair }
}

async function waitForRecord(server, publicKey, timeout = 5000) {
  const start = Date.now()
  while (Date.now() - start < timeout) {
    const record = await server.lookup(publicKey)
    if (record) return record
    await delay(100)
  }
  return null
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}