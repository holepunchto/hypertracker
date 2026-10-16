const HyperDHT = require('hyperdht')
const ReadyResource = require('ready-resource')
const b4a = require('b4a')
const HyperTrackerClient = require('./client')
const safetyCatch = require('safety-catch')

/**
 * Fan-out client for multiple HyperTracker servers.
 * Emits `connect` with the inner client, and `announce` once per unique bump.
 */
class HyperTrackerMultiClient extends ReadyResource {
  /**
   * @param {Buffer[]} remotePublicKeys Tracker public keys
   * @param {{ bootstrap?: any, dht?: any }} [opts]
   */
  constructor(remotePublicKeys, { bootstrap, dht = new HyperDHT({ bootstrap }) } = {}) {
    super()

    this.dht = dht
    this._clients = new Map()
    this._bumps = new Map()
    this._shouldReconnect = false
    this._suspended = false
    this.setKeys(remotePublicKeys)
  }

  /** @returns {HyperTrackerClient[]} */
  get clients() {
    return [...this._clients.values()]
  }

  _onannounce(bump) {
    const id = b4a.toString(bump.publicKey, 'hex')
    const seen = this._bumps.get(id)

    if (seen >= bump.bumped) return

    this._bumps.set(id, bump.bumped)
    this.emit('announce', bump)
  }

  _addClient(key) {
    if (this._clients.has(key)) return

    const client = new HyperTrackerClient(b4a.from(key, 'hex'), {
      dht: this.dht,
      suspended: this._suspended,
      shouldReconnect: this._shouldReconnect
    })
    client.on('announce', (bump) => this._onannounce(bump))
    client.on('connect', () => this.emit('connect', client))
    this._clients.set(key, client)
  }

  /**
   * Replace the tracker key set.
   * Unchanged keys keep their client. Removed keys are closed.
   * New keys inherit suspend state but do not connect.
   * @param {Buffer[]} remotePublicKeys
   */
  setKeys(remotePublicKeys) {
    if (this.closing) return

    const newKeys = new Set(remotePublicKeys.map((x) => b4a.toString(x, 'hex')))
    const oldKeys = new Set(this._clients.keys())
    const clientToRemove = oldKeys.difference(newKeys)
    for (const key of newKeys) this._addClient(key)
    for (const key of clientToRemove) {
      this._clients.get(key).close().catch(safetyCatch)
      this._clients.delete(key)
    }
  }

  /** Connect to every tracker. No-op for clients that already connected. */
  connect() {
    this._shouldReconnect = true
    this._runClients(this.clients, (client) => client.connect())
  }

  /**
   * Subscribe to a key on every tracker.
   * @param {Buffer} publicKey
   * @param {{ since?: number }} [opts]
   */
  subscribe(publicKey, opts) {
    this._shouldReconnect = true
    this._runClients(this.clients, (client) => client.subscribe(publicKey, opts))
  }

  /**
   * Unsubscribe a key on every tracker.
   * @param {Buffer} publicKey
   */
  unsubscribe(publicKey) {
    this._shouldReconnect = true
    this._bumps.delete(b4a.toString(publicKey, 'hex'))
    this._runClients(this.clients, (client) => client.unsubscribe(publicKey))
  }

  /**
   * Announce a key pair to every tracker.
   * @param {{ publicKey: Buffer, secretKey: Buffer }} keyPair
   * @param {{ bump?: number }} [opts]
   */
  announce(keyPair, { bump = Date.now() } = {}) {
    this._shouldReconnect = true
    this._runClients(this.clients, (client) => client.announce(keyPair, { bump }))
  }

  /** Stop all tracker connections. */
  async suspend() {
    this._suspended = true
    await this._runClientsAsync(this.clients, (client) => client.suspend())
  }

  /** Resume tracker connections that were connected before suspend. */
  resume() {
    this._suspended = false
    this._runClients(this.clients, (client) => client.resume())
  }

  async _close() {
    this._bumps.clear()
    await this._runClientsAsync(this.clients, (client) => client.close())
  }

  _runClients(clients, handler) {
    const errors = []
    for (const client of clients) {
      try {
        handler(client)
      } catch (error) {
        errors.push(error)
      }
    }
    if (errors.length) {
      throw new AggregateError(errors, 'One or more clients failed to handle error')
    }
  }

  async _runClientsAsync(clients, handler) {
    const results = await Promise.allSettled(clients.map((client) => handler(client)))
    const errors = results.filter((x) => x.status === 'rejected').map((x) => x.reason)
    if (errors.length) {
      throw new AggregateError(errors, 'One or more clients failed to handle error')
    }
  }
}

module.exports = HyperTrackerMultiClient
