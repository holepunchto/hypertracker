import createTestnet from 'hyperdht/testnet.js'
import crypto from 'hypercore-crypto'
import { HyperDiscovery, HyperDiscoveryClient } from './index.js'

const testnet = await createTestnet()

const s = new HyperDiscovery('/tmp/hyperdiscovery', { bootstrap: testnet.bootstrap })
await s.ready()

const p1 = new HyperDiscoveryClient(s.publicKey, { bootstrap: testnet.bootstrap })
const p2 = new HyperDiscoveryClient(s.publicKey, { bootstrap: testnet.bootstrap })

const k = crypto.keyPair()

p1.on('announce', function (ann) {
  console.log(ann, '<--')
})

p1.subscribe(k.publicKey)
p2.announce(k)
