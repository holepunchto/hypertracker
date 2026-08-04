const path = require('path')
const Hyperschema = require('hyperschema')
const HyperDB = require('hyperdb/builder')

const SCHEMA_DIR = path.join(__dirname, './spec/hyperschema')
const DB_DIR = path.join(__dirname, './spec/hyperdb')

const schema = Hyperschema.from(SCHEMA_DIR, { versioned: false })

const trackerSchema = schema.namespace('hypertracker')

trackerSchema.register({
  name: 'manifest',
  fields: [
    {
      name: 'version',
      type: 'uint',
      required: true
    },
    {
      name: 'seed',
      type: 'fixed32',
      required: true
    }
  ]
})

trackerSchema.register({
  name: 'swarm',
  fields: [
    {
      name: 'publicKey',
      type: 'fixed32',
      required: true
    },
    {
      name: 'bumped',
      type: 'uint'
    },
    {
      name: 'updated',
      type: 'uint'
    },
    {
      name: 'signature',
      type: 'fixed64'
    }
  ]
})

trackerSchema.register({
  name: 'announce',
  fields: [
    {
      name: 'bump',
      type: 'uint'
    }
  ]
})

trackerSchema.register({
  name: 'announce-to-swarm',
  fields: [
    {
      name: 'publicKey',
      type: 'fixed32',
      required: true
    },
    {
      name: 'announce',
      type: '@hypertracker/announce',
      required: true
    },
    {
      name: 'signature',
      type: 'fixed64',
      required: true
    }
  ]
})

trackerSchema.register({
  name: 'subscribe-to-swarm',
  fields: [
    {
      name: 'publicKey',
      type: 'fixed32',
      required: true
    },
    {
      name: 'since',
      type: 'uint',
      required: true
    }
  ]
})

trackerSchema.register({
  name: 'unsubscribe-to-swarm',
  fields: [
    {
      name: 'publicKey',
      type: 'fixed32',
      required: true
    }
  ]
})

trackerSchema.register({
  name: 'bump-from-swarm',
  fields: [
    {
      name: 'publicKey',
      type: 'fixed32',
      required: true
    },
    {
      name: 'bumped',
      type: 'uint',
      required: true
    }
  ]
})

Hyperschema.toDisk(schema)

const db = HyperDB.from(SCHEMA_DIR, DB_DIR)

const trackerDb = db.namespace('hypertracker')

trackerDb.collections.register({
  name: 'manifest',
  schema: '@hypertracker/manifest',
  key: []
})

trackerDb.collections.register({
  name: 'swarms',
  schema: '@hypertracker/swarm',
  key: ['publicKey']
})

trackerDb.indexes.register({
  name: 'swarms-by-updated',
  collection: '@hypertracker/swarms',
  key: ['updated'],
  unique: true
})

HyperDB.toDisk(db)
