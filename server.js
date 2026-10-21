const crypto = require('hypercore-crypto')
const HyperDHT = require('hyperdht')
const ReadyResource = require('ready-resource')
const b4a = require('b4a')
const c = require('compact-encoding')
const HyperDB = require('hyperdb')
const ScopeLock = require('scope-lock')
const {
  NS_ANNOUNCE,
  PROTOCOL,
  AnnouncePayload,
  Announce,
  Subscribe,
  Unsubscribe,
  Bump,
  getMuxer,
  unsupported,
  noop
} = require('./lib')

const TIME_SLACK = 60_000

class HyperTracker extends ReadyResource {
  constructor(storage, { bootstrap, dht = new HyperDHT({ bootstrap }) } = {}) {
    super()

    this.dht = dht
    this.db = HyperDB.rocks(storage, require('./spec/hyperdb'))
    this.subs = new Map()
    this._announces = new PromiseQueue()

    this._flushTimeout = null
    this._flushing = null
    this._server = null
    this._manifest = null

    this._writeLock = new ScopeLock()

    this.stats = {
      streamsAdded: 0,
      streamsEnded: 0,
      subscriptionsAdded: 0,
      subscriptionsRemoved: 0,
      announces: 0,
      announcesSent: 0,
      flushErrors: 0,
      onsubscribeCount: 0,
      onunsubscribeCount: 0,
      onannounceCount: 0
    }

    this.ready().catch(noop)
  }

  get publicKey() {
    return this._server && this._server.address().publicKey
  }

  async _open() {
    await this._init()

    this._flushBackground().catch(noop)

    this._server = this.dht.createServer()
    this._server.on('connection', this.addStream.bind(this))

    await this._server.listen(crypto.keyPair(this._manifest.seed))
  }

  async _init() {
    this._manifest = await this.db.get('@hyperdiscovery/manifest')
    if (this._manifest) return

    this._manifest = { version: 0, seed: crypto.randomBytes(32) }
    await this.db.insert('@hyperdiscovery/manifest', this._manifest)
    await this.db.flush()
  }

  async _close() {
    if (this._flushTimeout) clearTimeout(this._flushTimeout)
    if (this._flushing) await this._flushing
    this._flushTimeout = null
    if (this._server) await this._server.close()

    this._announces.destroy()
    await this._announces.drain()

    this._writeLock.destroy()
    await this._writeLock.flush()

    await this.db.flush()
    await this.db.close()
  }

  async _flushBackground() {
    while (!this.closing) {
      await new Promise((resolve) => {
        this._flushTimeout = setTimeout(resolve, 120_000)
      })

      this._flushTimeout = null
      if (this.closing) return

      this._flushing = this._flush()
      await this._flushing
      this._flushing = null
    }
  }

  async _flush() {
    if (!(await this._writeLock.lock())) return
    try {
      await this.db.flush()
    } catch {
      this.stats.flushErrors++
    } finally {
      this._writeLock.unlock()
    }
  }

  _addSub(channel, id, since) {
    let subs = this.subs.get(id)

    if (!subs) {
      subs = new Map()
      this.subs.set(id, subs)
    }

    if (!subs.has(channel)) this.stats.subscriptionsAdded++
    subs.set(channel, since)
  }

  _removeSub(channel, id) {
    const subs = this.subs.get(id)
    if (!subs) return
    if (subs.delete(channel)) this.stats.subscriptionsRemoved++
    if (!subs.size) this.subs.delete(id)
  }

  addStream(stream) {
    this.stats.streamsAdded++
    const muxer = getMuxer(stream)
    const tracker = this
    const subs = new Set()

    muxer.pair({ protocol: PROTOCOL }, onpair)
    onpair()

    function onpair() {
      const channel = muxer.createChannel({
        protocol: PROTOCOL,
        messages: [
          { encoding: Subscribe, onmessage: onsubscribe },
          { encoding: Unsubscribe, onmessage: onunsubscribe },
          { encoding: Announce, onmessage: onannounce },
          { encoding: Bump, onmessage: unsupported }
        ],
        onclose() {
          tracker.stats.streamsEnded++
          for (const id of subs) tracker._removeSub(channel, id)
        }
      })

      if (!channel) return

      channel.open()

      async function onsubscribe(m) {
        tracker.stats.onsubscribeCount++
        const id = b4a.toString(m.publicKey, 'hex')
        subs.add(id)
        tracker._addSub(channel, id, m.since)

        const v = await tracker.lookup(m.publicKey)
        if (v && v.bumped >= m.since) channel.messages[3].send(v)
      }

      function onunsubscribe(m) {
        tracker.stats.onunsubscribeCount++
        const id = b4a.toString(m.publicKey, 'hex')
        subs.delete(id)
        tracker._removeSub(channel, id)
      }

      function onannounce(m) {
        tracker.stats.onannounceCount++
        return tracker.announce(m, channel)
      }
    }
  }

  async lookup(publicKey) {
    const v = await this.db.get('@hyperdiscovery/swarms', { publicKey })
    return v
  }

  announce(m, channel) {
    return this._announces.add(b4a.toString(m.publicKey, 'hex'), () => this._announce(m, channel))
  }

  async _announce(m, channel) {
    if (m.announce.bump > Date.now() + TIME_SLACK) return false

    const state = { buffer: null, start: 0, end: 0 }

    c.fixed32.preencode(state, NS_ANNOUNCE)
    AnnouncePayload.preencode(state, m.announce)

    state.buffer = b4a.allocUnsafe(state.end)

    c.fixed32.encode(state, NS_ANNOUNCE)
    AnnouncePayload.encode(state, m.announce)

    if (!crypto.verify(state.buffer, m.signature, m.publicKey)) return false

    const v = await this.db.get('@hyperdiscovery/swarms', { publicKey: m.publicKey })
    if (v && v.bumped >= m.announce.bump) return false

    const doc = {
      publicKey: m.publicKey,
      bumped: m.announce.bump,
      updated: Date.now(),
      signature: m.signature
    }

    if (!(await this._writeLock.lock())) return false
    try {
      await this.db.insert('@hyperdiscovery/swarms', doc)
    } finally {
      this._writeLock.unlock()
    }

    this.stats.announces++

    const subs = this.subs.get(b4a.toString(m.publicKey, 'hex'))
    if (subs) {
      for (const [ch, since] of subs) {
        if (ch === channel) continue
        if (doc.bumped < since) continue
        this.stats.announcesSent++
        ch.messages[3].send(doc)
      }
    }

    return true
  }

  registerMetrics(promClient) {
    const tracker = this

    new promClient.Gauge({
      name: 'hypertracker_streams_added',
      help: 'Hypertracker streams added',
      collect() {
        this.set(tracker.stats.streamsAdded)
      }
    })

    new promClient.Gauge({
      name: 'hypertracker_streams_ended',
      help: 'Hypertracker streams ended',
      collect() {
        this.set(tracker.stats.streamsEnded)
      }
    })

    new promClient.Gauge({
      name: 'hypertracker_subscriptions_added',
      help: 'Hypertracker subscriptions added',
      collect() {
        this.set(tracker.stats.subscriptionsAdded)
      }
    })

    new promClient.Gauge({
      name: 'hypertracker_subscriptions_removed',
      help: 'Hypertracker subscriptions removed',
      collect() {
        this.set(tracker.stats.subscriptionsRemoved)
      }
    })

    new promClient.Gauge({
      name: 'hypertracker_subscription_keys',
      help: 'Hypertracker distinct subscribed keys',
      collect() {
        this.set(tracker.subs.size)
      }
    })

    new promClient.Gauge({
      name: 'hypertracker_announces',
      help: 'Hypertracker announces',
      collect() {
        this.set(tracker.stats.announces)
      }
    })

    new promClient.Gauge({
      name: 'hypertracker_announces_sent',
      help: 'Hypertracker announces sent',
      collect() {
        this.set(tracker.stats.announcesSent)
      }
    })

    new promClient.Gauge({
      name: 'hypertracker_flush_errors',
      help: 'Hypertracker background flushes that failed',
      collect() {
        this.set(tracker.stats.flushErrors)
      }
    })

    new promClient.Gauge({
      name: 'hypertracker_onsubscribe_count',
      help: 'Hypertracker onsubscribe count',
      collect() {
        this.set(tracker.stats.onsubscribeCount)
      }
    })

    new promClient.Gauge({
      name: 'hypertracker_onunsubscribe_count',
      help: 'Hypertracker onunsubscribe count',
      collect() {
        this.set(tracker.stats.onunsubscribeCount)
      }
    })

    new promClient.Gauge({
      name: 'hypertracker_onannounce_count',
      help: 'Hypertracker onannounce count',
      collect() {
        this.set(tracker.stats.onannounceCount)
      }
    })
  }
}

module.exports = HyperTracker

class PromiseQueue {
  constructor() {
    this._tails = new Map()
    this._destroyed = false
  }

  add(id, fn) {
    if (this._destroyed) return Promise.resolve(false)
    const tail = this._tails.get(id) || Promise.resolve()
    const next = tail.then(fn, fn)
    this._tails.set(id, next)
    return next.finally(() => {
      if (this._tails.get(id) === next) this._tails.delete(id)
    })
  }

  destroy() {
    this._destroyed = true
  }

  async drain() {
    while (this._tails.size > 0) {
      await Promise.allSettled([...this._tails.values()])
    }
  }
}
