const { getEncoding } = require('./spec/hyperschema')
const crypto = require('hypercore-crypto')
const HyperDHT = require('hyperdht')
const ReadyResource = require('ready-resource')
const b4a = require('b4a')
const Protomux = require('protomux')
const c = require('compact-encoding')
const HyperDB = require('hyperdb')

// Keep the pre-rename string here: it's baked into signed announce/swarm
// bytes, so changing it would invalidate every already-persisted signature.
const [NS_ANNOUNCE] = crypto.namespace('hyperdiscovery', 1)
const TIME_SLACK = 60_000

const AnnouncePayload = getEncoding('@hyperdiscovery/announce')
const Announce = getEncoding('@hyperdiscovery/announce-to-swarm')
const Subscribe = getEncoding('@hyperdiscovery/subscribe-to-swarm')
const Unsubscribe = getEncoding('@hyperdiscovery/unsubscribe-to-swarm')
const Bump = getEncoding('@hyperdiscovery/bump-from-swarm')

class HyperTracker extends ReadyResource {
  constructor(storage, { bootstrap, dht = new HyperDHT({ bootstrap }) } = {}) {
    super()

    this.dht = dht
    this.db = HyperDB.rocks(storage, require('./spec/hyperdb'))
    this.subs = new Map()

    this._flushTimeout = null
    this._flushing = null
    this._server = null
    this._manifest = null

    this.stats = {
      streamsAdded: 0,
      streamsEnded: 0,
      subscriptionsAdded: 0,
      subscriptionsRemoved: 0,
      announces: 0,
      announcesSent: 0,
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
    await this.db.close()
  }

  async _flushBackground() {
    while (!this.closing) {
      await new Promise((resolve) => {
        this._flushTimeout = setTimeout(resolve, 120_000)
      })

      this._flushTimeout = null
      if (this.closing) return

      this._flushing = this.db.flush()
      await this._flushing
      this._flushing = null
    }
  }

  _addSub(channel, id, since) {
    let subs = this.subs.get(id)

    if (!subs) {
      subs = new Map()
      this.subs.set(id, subs)
    }

    this.stats.subscriptionsAdded++
    subs.set(channel, since)
  }

  _removeSub(channel, id) {
    const subs = this.subs.get(id)
    if (!subs) return
    this.stats.subscriptionsRemoved++
    subs.delete(channel)
    if (!subs.size) this.subs.delete(id)
  }

  addStream(stream) {
    this.stats.streamsAdded++
    const muxer = getMuxer(stream)
    const tracker = this
    const subs = new Set()

    // Keep the pre-rename protocol name here: it's the Protomux handshake
    // string both sides pair on, so changing it breaks pairing with any peer
    // still running the old name until every peer upgrades together.
    muxer.pair({ protocol: 'hyperdiscovery' }, onpair)
    onpair()

    function onpair() {
      const channel = muxer.createChannel({
        protocol: 'hyperdiscovery',
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

  async announce(m, channel) {
    if (m.announce.bump <= 0 || m.announce.bump > Date.now() + TIME_SLACK) return false

    const state = { buffer: null, start: 0, end: 0 }

    c.fixed32.preencode(state, NS_ANNOUNCE)
    AnnouncePayload.preencode(state, m.announce)

    state.buffer = b4a.allocUnsafe(state.end)

    c.fixed32.encode(state, NS_ANNOUNCE)
    AnnouncePayload.encode(state, m.announce)

    if (!crypto.verify(state.buffer, m.signature, m.publicKey)) return false

    const v = await this.db.get('@hyperdiscovery/swarms', { publicKey: m.publicKey })
    if (v && v.bumped >= m.announce.bump) return false

    this.stats.announces++

    const doc = {
      publicKey: m.publicKey,
      bumped: m.announce.bump,
      updated: Date.now(),
      signature: m.signature
    }

    await this.db.insert('@hyperdiscovery/swarms', doc)

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

class HyperTrackerClient extends ReadyResource {
  constructor(remotePublicKey, { bootstrap, dht = new HyperDHT({ bootstrap }) } = {}) {
    super()

    this.remotePublicKey = remotePublicKey
    this.dht = dht
    this.connection = null
    this.muxer = null
    this.channel = null
    this.suspended = false
    this.connecting = false

    this._retryTimeout = null
    this._retryResolve = null
    this._shouldReconnect = false
  }

  async suspend() {
    this.suspended = true
    this._clearRetry()
    if (!this.connection) return
    this.connection.destroy()
    this.connecting = null
    this.channel = null
    this.muxer = null
    if (this.connection.destroyed) return
    await new Promise((resolve) => this.connection.on('close', resolve))
  }

  resume() {
    this.suspended = false
    if (this._shouldReconnect && !this.closing) this._reconnect()
  }

  connect() {
    if (!this.channel) this._reconnect()
  }

  async _reconnect() {
    if (this.connecting) return this.channel
    this.connecting = true
    this._shouldReconnect = true

    let strikes = 0

    while (!this.closing && !this.suspended) {
      const connection = (this.connection = this.dht.connect(this.remotePublicKey))

      this.muxer = getMuxer(this.connection)
      this.channel = this.muxer.createChannel({
        userData: this,
        // Must match the server's protocol name in addStream() above.
        protocol: 'hyperdiscovery',
        messages: [
          { encoding: Subscribe, onmessage: unsupported },
          { encoding: Unsubscribe, onmessage: unsupported },
          { encoding: Announce, onmessage: unsupported },
          { encoding: Bump, onmessage: onbump }
        ]
      })

      if (!this.channel) break
      this.channel.open()

      await new Promise((resolve) => {
        connection.on('connect', done)
        connection.on('error', done)

        function done() {
          connection.off('connect', done)
          connection.off('error', done)
          resolve()
        }
      })

      if (this.closing || this.suspended) {
        connection.on('error', noop)
        connection.destroy()
        break
      }

      if (!connection.destroyed && !connection.destroying) {
        connection.on('close', this._reconnect.bind(this))
        break
      }

      strikes++

      await new Promise((resolve) => {
        this._retryResolve = resolve
        this._retryTimeout = setTimeout(resolve, strikes < 3 ? 5_000 : 15_000)
      })

      this._retryResolve = null
      this._retryTimeout = null
    }

    this.connecting = false
    if (this.closing || this.suspended) return this.channel

    this.emit('connect')
    return this.channel
  }

  _close() {
    if (this.connection) this.connection.destroy()
    this._clearRetry()
  }

  _clearRetry() {
    if (!this._retryTimeout) return
    clearTimeout(this._retryTimeout)
    this._retryResolve()
    this._retryResolve = null
    this._retryTimeout = null
  }

  _onbump(bump) {
    this.emit('announce', bump)
  }

  _getChannel() {
    if (this.channel) return this.channel
    this._reconnect()
    return this.channel
  }

  cork() {
    const channel = this._getChannel()
    if (channel) channel.cork()
  }

  uncork() {
    const channel = this._getChannel()
    if (channel) channel.uncork()
  }

  subscribe(publicKey, { since = 0 } = {}) {
    const channel = this._getChannel()
    if (!channel) return
    channel.messages[0].send({
      publicKey,
      since
    })
  }

  unsubscribe(publicKey) {
    const channel = this._getChannel()
    if (!channel) return
    channel.messages[1].send({
      publicKey
    })
  }

  async announce(keyPair, { bump = Date.now() } = {}) {
    const channel = this._getChannel()
    if (!channel) return

    const ann = { bump }
    const state = { buffer: null, start: 0, end: 0 }

    c.fixed32.preencode(state, NS_ANNOUNCE)
    AnnouncePayload.preencode(state, ann)

    state.buffer = b4a.allocUnsafe(state.end)

    c.fixed32.encode(state, NS_ANNOUNCE)
    AnnouncePayload.encode(state, ann)

    const signature = crypto.sign(state.buffer, keyPair.secretKey)
    const m = { publicKey: keyPair.publicKey, announce: ann, signature }

    channel.messages[2].send(m)
  }
}

module.exports = { HyperTracker, HyperTrackerClient }

function getMuxer(stream) {
  if (Protomux.isProtomux(stream)) return stream
  if (stream.noiseStream.userData) return stream.noiseStream.userData
  const mux = Protomux.from(stream.noiseStream)
  stream.noiseStream.userData = mux
  return mux
}

function onbump(bump, channel) {
  channel.userData._onbump(bump)
}

function unsupported() {
  throw new Error('Method not supported')
}

function noop() {}
