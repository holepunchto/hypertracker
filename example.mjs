import createTestnet from 'hyperdht/testnet.js'
import crypto from 'hypercore-crypto'
import { HyperTracker, HyperTrackerClient } from './index.js'

const testnet = await createTestnet()

const s = new HyperTracker('/tmp/hypertracker', { bootstrap: testnet.bootstrap })
await s.ready()

const p1 = new HyperTrackerClient(s.publicKey, { bootstrap: testnet.bootstrap })
const p2 = new HyperTrackerClient(s.publicKey, { bootstrap: testnet.bootstrap })

const k = crypto.keyPair()

p1.on('announce', function (ann) {
  console.log(ann, '<--')
})

p1.subscribe(k.publicKey)
p2.announce(k)
