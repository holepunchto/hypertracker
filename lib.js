const { getEncoding } = require('./spec/hyperschema')
const crypto = require('hypercore-crypto')
const Protomux = require('protomux')

// Keep the pre-rename string here: it's baked into signed announce/swarm
// bytes, so changing it would invalidate every already-persisted signature.
const [NS_ANNOUNCE] = crypto.namespace('hyperdiscovery', 1)

// Keep the pre-rename protocol name here: it's the Protomux handshake
// string both sides pair on, so changing it breaks pairing with any peer
// still running the old name until every peer upgrades together.
const PROTOCOL = 'hyperdiscovery'

const AnnouncePayload = getEncoding('@hyperdiscovery/announce')
const Announce = getEncoding('@hyperdiscovery/announce-to-swarm')
const Subscribe = getEncoding('@hyperdiscovery/subscribe-to-swarm')
const Unsubscribe = getEncoding('@hyperdiscovery/unsubscribe-to-swarm')
const Bump = getEncoding('@hyperdiscovery/bump-from-swarm')

function getMuxer(stream) {
  if (Protomux.isProtomux(stream)) return stream
  if (stream.noiseStream.userData) return stream.noiseStream.userData
  const mux = Protomux.from(stream.noiseStream)
  stream.noiseStream.userData = mux
  return mux
}

function unsupported() {
  throw new Error('Method not supported')
}

function noop() {}

module.exports = {
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
}
