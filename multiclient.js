const HyperDHT = require('hyperdht')
const ReadyResource = require('ready-resource')
const b4a = require('b4a')
const HyperTrackerClient = require('./client')
const { noop } = require('./lib')

class HyperTrackerMultiClient extends ReadyResource {
  constructor(remotePublicKeys, { bootstrap, dht = new HyperDHT({ bootstrap }) } = {}) {
    super()

    this.dht = dht
    this._clients = new Map()
    this._bumps = new Map()
    this._connected = false
    this._suspended = false
    this.setKeys(remotePublicKeys)
  }

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

    const client = new HyperTrackerClient(b4a.from(key, 'hex'), { dht: this.dht })
    client.on('announce', (bump) => this._onannounce(bump))
    client.on('connect', () => this.emit('connect', client))

    this._clients.set(key, client)

    if (this._suspended) client.suspend()
    if (this._connected) client.connect()
  }

  setKeys(remotePublicKeys) {
    if (this.closing || this.closed) return

    const newKeys = new Set(remotePublicKeys.map((x) => b4a.toString(x, 'hex')))
    const oldKeys = new Set(this._clients.keys())
    const clientToRemove = oldKeys.difference(newKeys)
    for (const key of newKeys) this._addClient(key)
    for (const key of clientToRemove) {
      this._clients.get(key).close().catch(noop)
      this._clients.delete(key)
    }
  }

  connect() {
    this._connected = true
    this._runClients(this.clients, (client) => client.connect())
  }

  subscribe(publicKey, opts) {
    this._connected = true
    this._runClients(this.clients, (client) => client.subscribe(publicKey, opts))
  }

  unsubscribe(publicKey) {
    this._connected = true
    this._bumps.delete(b4a.toString(publicKey, 'hex'))
    this._runClients(this.clients, (client) => client.unsubscribe(publicKey))
  }

  announce(keyPair, { bump = Date.now() } = {}) {
    this._connected = true
    this._runClients(this.clients, (client) => client.announce(keyPair, { bump }))
  }

  async suspend() {
    this._suspended = true
    await this._runClientsAsync(this.clients, (client) => client.suspend())
  }

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
