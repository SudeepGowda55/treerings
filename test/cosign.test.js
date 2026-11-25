import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { cosignedSubtreeBytes, witnessFromSeed, cosign, verifyCosignature, originOf } from '../src/cosign.js'

const head = { url: 'https://ct.cloudflare.com/logs/nimbus2026/', treeSize: 6828176246, rootHash: createHash('sha256').update('root').digest() }
const w = witnessFromSeed('treerings.witness/test', Buffer.alloc(32, 7))

test('the signed message is the c2sp CosignedSubtree structure', () => {
  const b = cosignedSubtreeBytes({ cosigner: 'w', timestamp: 1, origin: 'o', end: 5, hash: Buffer.alloc(32) })
  assert.equal(b.subarray(0, 12).toString(), 'subtree/v1\n\0')
  assert.equal(b.length, 12 + 2 + 8 + 2 + 8 + 8 + 32)
  assert.equal(b.readBigUInt64BE(14), 1n)
  assert.throws(() => cosignedSubtreeBytes({ cosigner: 'w', timestamp: 1, origin: 'o', start: 2, end: 5, hash: Buffer.alloc(32) }))
  assert.equal(originOf(head), 'ct.cloudflare.com/logs/nimbus2026')
})

test('an ML-DSA-87 cosignature verifies, and any change to what it covers does not', () => {
  const c = cosign(w, head, 1795600000)
  assert.ok(verifyCosignature(w.publicKey, c))
  assert.equal(c.signature.length, 4627) // ML-DSA-87 signature size
  assert.ok(c.line.startsWith('— treerings.witness/test '))
  assert.equal(verifyCosignature(w.publicKey, { ...c, treeSize: c.treeSize + 1 }), false)
  assert.equal(verifyCosignature(w.publicKey, { ...c, rootHash: Buffer.alloc(32) }), false)
  assert.equal(verifyCosignature(w.publicKey, { ...c, timestamp: c.timestamp + 1 }), false)
  assert.equal(verifyCosignature(witnessFromSeed('other', Buffer.alloc(32, 7)).publicKey, c), false)
})

test('the same seed always gives the same witness key', () => {
  assert.ok(witnessFromSeed('treerings.witness/test', Buffer.alloc(32, 7)).publicKey.equals(w.publicKey))
})
