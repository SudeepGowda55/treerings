import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { verifyConsistency, parseSth } from '../src/ct.js'

// A reference Merkle tree (RFC 9162 section 2.1) and its consistency proofs, to test the verifier on every pair.
const H = (...p) => createHash('sha256').update(Buffer.concat(p)).digest()
const leaf = i => H(Buffer.from([0]), Buffer.from(`leaf ${i}`))
const k = n => { let p = 1; while (p * 2 < n) p *= 2; return p } // largest power of two smaller than n
function mth(leaves) {
  if (leaves.length === 1) return leaves[0]
  const s = k(leaves.length)
  return H(Buffer.from([1]), mth(leaves.slice(0, s)), mth(leaves.slice(s)))
}
function subproof(m, leaves, complete) {
  const n = leaves.length
  if (m === n) return complete ? [] : [mth(leaves)]
  const s = k(n)
  if (m <= s) return [...subproof(m, leaves.slice(0, s), complete), mth(leaves.slice(s))]
  return [...subproof(m - s, leaves.slice(s), false), mth(leaves.slice(0, s))]
}

test('accepts every honest consistency proof for trees of 1 to 40 leaves', () => {
  const all = Array.from({ length: 40 }, (_, i) => leaf(i))
  for (let n = 1; n <= 40; n++) for (let m = 1; m <= n; m++) {
    const proof = m === n ? [] : subproof(m, all.slice(0, n), true)
    assert.ok(verifyConsistency(m, n, mth(all.slice(0, m)), mth(all.slice(0, n)), proof), `${m} -> ${n}`)
  }
})

test('rejects a rewritten history, a tampered proof and a shrinking tree', () => {
  const all = Array.from({ length: 30 }, (_, i) => leaf(i))
  const proof = subproof(11, all.slice(0, 27), true)
  const forked = [...all.slice(0, 5), leaf(999), ...all.slice(6)] // entry 5 swapped after the fact
  assert.equal(verifyConsistency(11, 27, mth(forked.slice(0, 11)), mth(all.slice(0, 27)), proof), false)
  const bent = proof.map((p, i) => (i === 1 ? H(p) : p))
  assert.equal(verifyConsistency(11, 27, mth(all.slice(0, 11)), mth(all.slice(0, 27)), bent), false)
  assert.equal(verifyConsistency(27, 11, mth(all.slice(0, 27)), mth(all.slice(0, 11)), proof), false)
})

test("a real log's two signed tree heads and its consistency proof between them", () => {
  const f = JSON.parse(readFileSync(new URL('./fixtures/nimbus2026-consistency.json', import.meta.url)))
  const a = parseSth(f.log, f.first), b = parseSth(f.log, f.second)
  assert.ok(a.valid && b.valid, 'both heads carry the log\'s own valid signature')
  const proof = f.proof.map(p => Buffer.from(p, 'base64'))
  assert.ok(verifyConsistency(a.treeSize, b.treeSize, a.rootHash, b.rootHash, proof))
  assert.equal(verifyConsistency(a.treeSize, b.treeSize, b.rootHash, a.rootHash, proof), false)
})
