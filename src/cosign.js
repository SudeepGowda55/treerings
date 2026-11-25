// Witness cosignatures. The signed message is c2sp tlog-cosignature's CosignedSubtree, byte for byte; the key is
// ML-DSA-87 instead of the spec's ML-DSA-44, because ML-DSA-87 is what QoreChain verifies on chain.
import { createHash } from 'node:crypto'
import { mldsa87, shake256 } from '@qorechain/pqc'

const LABEL = Buffer.from('subtree/v1\n\0') // 12 bytes, from the spec
const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b }
const vec8 = s => { const b = Buffer.from(s); if (b.length < 1 || b.length > 255) throw new Error('name/origin must be 1..255 bytes'); return Buffer.concat([Buffer.from([b.length]), b]) }

// For a whole checkpoint: start 0, end = tree size, timestamp = when the witness signed it (seconds).
export function cosignedSubtreeBytes({ cosigner, timestamp, origin, start = 0, end, hash }) {
  if (hash.length !== 32) throw new Error('hash must be 32 bytes')
  if (start !== 0 && timestamp !== 0) throw new Error('a subtree cosignature (start > 0) has timestamp 0')
  return Buffer.concat([LABEL, vec8(cosigner), u64(timestamp), vec8(origin), u64(start), u64(end), hash])
}

// RFC 6962 logs have no origin line; we use the log's URL without the scheme or trailing slash, as static-ct does.
export const originOf = head => head.origin ?? head.url.replace(/^https?:\/\//, '').replace(/\/$/, '')

// A witness key from a 32-byte seed, so the operator can rebuild it from its own secret.
export function witnessFromSeed(name, seed) {
  const { publicKey, secretKey } = mldsa87.keygen(shake256(Buffer.concat([Buffer.from('treerings witness\n' + name + '\n'), seed]), 32))
  const keyId = createHash('sha256').update(Buffer.concat([Buffer.from(name + '\n'), Buffer.from([0xff]), publicKey])).digest().subarray(0, 4)
  return { name, publicKey: Buffer.from(publicKey), secretKey, keyId }
}

export function cosign(witness, head, timestamp = Math.floor(Date.now() / 1000)) {
  const msg = cosignedSubtreeBytes({ cosigner: witness.name, timestamp, origin: originOf(head), end: head.treeSize, hash: head.rootHash })
  const signature = Buffer.from(mldsa87.sign(witness.secretKey, msg))
  // signed-note line: key ID || timestamp || signature (0xff: experimental ML-DSA-87 type, not a c2sp type yet)
  const line = `— ${witness.name} ${Buffer.concat([witness.keyId, u64(timestamp), signature]).toString('base64')}`
  return { cosigner: witness.name, timestamp, origin: originOf(head), treeSize: head.treeSize, rootHash: head.rootHash, signature, line }
}

export function verifyCosignature(publicKey, c) {
  const msg = cosignedSubtreeBytes({ cosigner: c.cosigner, timestamp: c.timestamp, origin: c.origin, end: c.treeSize, hash: c.rootHash })
  return mldsa87.verify(publicKey, msg, c.signature)
}
