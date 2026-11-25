import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { encodePost, decodePost, MAX_POST } from '../src/post.js'
import { witnessFromSeed, cosign, verifyCosignature } from '../src/cosign.js'

test('a cosignature post round-trips, fits the 6 KiB cap, and still verifies', () => {
  const w = witnessFromSeed('treerings.witness/test', Buffer.alloc(32, 7))
  const head = { url: 'https://ct.cloudflare.com/logs/nimbus2026/', treeSize: 6828176246, rootHash: createHash('sha256').update('r').digest() }
  const c = cosign(w, head, 1795600000)
  const fields = { logId: Buffer.alloc(32, 9).toString('base64'), origin: c.origin, treeSize: c.treeSize, rootHash: c.rootHash, logTimestamp: 1795599999123, logSignature: Buffer.alloc(75, 3), witnessTimestamp: c.timestamp, signature: c.signature }
  const bytes = encodePost(fields)
  assert.ok(bytes.length <= MAX_POST)
  const d = decodePost(bytes)
  assert.deepEqual({ ...d, rootHash: [...d.rootHash], logSignature: [...d.logSignature], signature: [...d.signature] },
    { ...fields, rootHash: [...fields.rootHash], logSignature: [...fields.logSignature], signature: [...fields.signature] })
  assert.ok(verifyCosignature(w.publicKey, { cosigner: w.name, timestamp: d.witnessTimestamp, origin: d.origin, treeSize: d.treeSize, rootHash: d.rootHash, signature: d.signature }))
})

test('anything else in the open inbox is not a post', () => {
  assert.equal(decodePost(Buffer.from('hello')), undefined)
  assert.equal(decodePost(Buffer.concat([Buffer.from('TRC1'), Buffer.alloc(10)])), undefined)
})
