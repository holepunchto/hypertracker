import HyperDHT from 'hyperdht'
import createTestnet from 'hyperdht/testnet.js'
import crypto from 'hypercore-crypto'
import { HyperDiscovery, HyperDiscoveryClient } from './index.js'

const testnet = await createTestnet()
const dht = new HyperDHT({ bootstrap: testnet.bootstrap })

const server = dht.createServer()
await server.listen()

server.on('connection', c => {
  s.addStream(c)
})

const s = new HyperDiscovery('/tmp/hyperdiscovery')
const p1 = new HyperDiscoveryClient(dht.connect(server.address().publicKey))
const p2 = new HyperDiscoveryClient(dht.connect(server.address().publicKey))

const k = crypto.keyPair()

p1.on('announce', function (ann) {
  console.log(ann, '<--')
})

p1.subscribe(k.publicKey)
p2.announce(k)
