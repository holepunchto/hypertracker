const crypto = require('hypercore-crypto')
const HyperDHT = require('hyperdht')
const ReadyResource = require('ready-resource')
const b4a = require('b4a')
const c = require('compact-encoding')
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

class HyperTrackerClient extends ReadyResource {
  constructor(
    remotePublicKey,
    {
      bootstrap,
      dht = new HyperDHT({ bootstrap }),
      suspended = false,
      shouldReconnect = false
    } = {}
  ) {
    super()

    this.remotePublicKey = remotePublicKey
    this.dht = dht
    this.connection = null
    this.muxer = null
    this.channel = null
    this.suspended = suspended
    this.connecting = false

    this._retryTimeout = null
    this._retryResolve = null
    this._shouldReconnect = shouldReconnect
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
    if (!this.suspended) return
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
        protocol: PROTOCOL,
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

  announce(keyPair, { bump = Date.now() } = {}) {
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

module.exports = HyperTrackerClient

function onbump(bump, channel) {
  channel.userData._onbump(bump)
}
