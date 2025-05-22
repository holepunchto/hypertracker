const { getEncoding } = require('./spec/hyperschema')
const crypto = require('hypercore-crypto')
const EventEmitter = require('events')
const b4a = require('b4a')
const Protomux = require('protomux')
const c = require('compact-encoding')
const HyperDB = require('hyperdb')

const [NS_ANNOUNCE] = crypto.namespace('holepunchto/hyperdiscovery', 1)
const TIME_SLACK = 60_000

const AnnouncePayload = getEncoding('@hyperdiscovery/announce')
const Announce = getEncoding('@hyperdiscovery/announce-to-swarm')
const Subscribe = getEncoding('@hyperdiscovery/subscribe-to-swarm')
const Unsubscribe = getEncoding('@hyperdiscovery/unsubscribe-to-swarm')
const Bump = getEncoding('@hyperdiscovery/bump-from-swarm')

class HyperDiscovery {
  constructor (storage) {
    this.db = HyperDB.rocks(storage, require('./spec/hyperdb'))
    this.subs = new Map()
  }

  _addSub (channel, id, since) {
    let subs = this.subs.get(id)

    if (!subs) {
      subs = new Map()
      this.subs.set(id, subs)
    }

    subs.set(channel, since)
  }

  _removeSub (channel, id) {
    const subs = this.subs.get(id)
    if (!subs) return
    subs.delete(channel)
    if (!subs.size) this.subs.delete(id)
  }

  addStream (stream) {
    const muxer = getMuxer(stream)
    const tracker = this
    const subs = new Set()

    muxer.pair({ protocol: 'hyperdiscovery' }, onpair)
    onpair()

    function onpair () {
      const channel = muxer.createChannel({
        protocol: 'hyperdiscovery',
        messages: [
          { encoding: Subscribe, onmessage: onsubscribe },
          { encoding: Unsubscribe, onmessage: onunsubscribe },
          { encoding: Announce, onmessage: onannounce },
          { encoding: Bump, onmessage: unsupported }
        ],
        onclose () {
          for (const id of subs) tracker._removeSub(channel, id)
        }
      })

      if (!channel) return

      channel.open()

      async function onsubscribe (m) {
        const id = b4a.toString(m.publicKey, 'hex')
        subs.add(id)
        tracker._addSub(channel, id, m.since)

        const v = await tracker.lookup(m.publicKey)
        if (v && v.bumped >= m.since) channel.messages[3].send(v)
      }

      function onunsubscribe (m) {
        const id = b4a.toString(m.publicKey, 'hex')
        subs.delete(id)
        tracker._removeSub(channel, id)
      }

      function onannounce (m) {
        return tracker.announce(m, channel)
      }
    }
  }

  async lookup (publicKey) {
    const v = await this.db.get('@hyperdiscovery/swarms', { publicKey })
    return v
  }

  async announce (m, channel) {
    const state = { buffer: null, start: 0, end: 0 }

    c.fixed32.preencode(state, NS_ANNOUNCE)
    AnnouncePayload.preencode(state, m.announce)

    state.buffer = b4a.allocUnsafe(state.end)

    c.fixed32.encode(state, NS_ANNOUNCE)
    AnnouncePayload.encode(state, m.announce)

    if ((Date.now() + TIME_SLACK) > m.announce.bumped) return false
    if (!crypto.verify(state.buffer, m.signature, m.publicKey)) return false

    const v = await this.db.get('@hyperdiscovery/swarms', m.publicKey)
    if (v && v.bumped >= m.announce.bump) return false

    const doc = {
      publicKey: m.publicKey,
      bumped: m.announce.bump,
      updated: Date.now(),
      signature: m.signature
    }

    await this.db.insert('@hyperdiscovery/swarms', doc)
    await this.db.flush()

    const subs = this.subs.get(b4a.toString(m.publicKey, 'hex'))
    if (subs) {
      for (const [ch, since] of subs) {
        if (ch === channel) continue
        if (doc.bumped < since) continue
        ch.messages[3].send(doc)
      }
    }

    return true
  }
}

class HyperDiscoveryClient extends EventEmitter {
  constructor (stream) {
    super()

    this.stream = stream
    this.muxer = getMuxer(stream)

    this.channel = this.muxer.createChannel({
      userData: this,
      protocol: 'hyperdiscovery',
      messages: [
        { encoding: Subscribe, onmessage: unsupported },
        { encoding: Unsubscribe, onmessage: unsupported },
        { encoding: Announce, onmessage: unsupported },
        { encoding: Bump, onmessage: onbump }
      ]
    })

    this.channel.open()
  }

  _onbump (bump) {
    this.emit('announce', bump)
  }

  subscribe (publicKey, { since = 0 } = {}) {
    this.channel.messages[0].send({
      publicKey,
      since
    })
  }

  unsubscribe (publicKey) {
    this.channel.messages[1].send({
      publicKey
    })
  }

  announce (keyPair, { bump = Date.now() } = {}) {
    const ann = { bump }
    const state = { buffer: null, start: 0, end: 0 }

    c.fixed32.preencode(state, NS_ANNOUNCE)
    AnnouncePayload.preencode(state, ann)

    state.buffer = b4a.allocUnsafe(state.end)

    c.fixed32.encode(state, NS_ANNOUNCE)
    AnnouncePayload.encode(state, ann)

    const signature = crypto.sign(state.buffer, keyPair.secretKey)
    const m = { publicKey: keyPair.publicKey, announce: ann, signature }

    this.channel.messages[2].send(m)
  }
}

module.exports = { HyperDiscovery, HyperDiscoveryClient }

function getMuxer (stream) {
  if (Protomux.isProtomux(stream)) return stream
  if (stream.noiseStream.userData) return stream.noiseStream.userData
  const mux = Protomux.from(stream.noiseStream)
  stream.noiseStream.userData = mux
  return mux
}

function onbump (bump, channel) {
  channel.userData._onbump(bump)
}

function unsupported () {
  throw new Error('Method not supported')
}
