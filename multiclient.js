const HyperDHT = require('hyperdht')
const ReadyResource = require('ready-resource')
const b4a = require('b4a')
const HyperTrackerClient = require('./client')

class HyperTrackerMultiClient extends ReadyResource {
  constructor(remotePublicKeys, { bootstrap, dht = new HyperDHT({ bootstrap }) } = {}) {
    super()

    this.dht = dht
    this.clients = remotePublicKeys.map((key) => new HyperTrackerClient(key, { dht }))

    this._bumps = new Map()

    for (const client of this.clients) {
      client.on('announce', (bump) => this._onannounce(bump))
      client.on('connect', () => this.emit('connect', client))
    }
  }

  _onannounce(bump) {
    const id = b4a.toString(bump.publicKey, 'hex')
    const seen = this._bumps.get(id)

    if (seen >= bump.bumped) return

    this._bumps.set(id, bump.bumped)
    this.emit('announce', bump)
  }

  connect() {
    this._runClients(this.clients, (client) => client.connect())
  }

  subscribe(publicKey, opts) {
    this._runClients(this.clients, (client) => client.subscribe(publicKey, opts))
  }

  unsubscribe(publicKey) {
    this._bumps.delete(b4a.toString(publicKey, 'hex'))
    this._runClients(this.clients, (client) => client.unsubscribe(publicKey))
  }

  announce(keyPair, { bump = Date.now() } = {}) {
    this._runClients(this.clients, (client) => client.announce(keyPair, { bump }))
  }

  async suspend() {
    await this._runClientsAsync(this.clients, (client) => client.suspend())
  }

  resume() {
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
