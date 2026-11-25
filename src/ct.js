// Certificate Transparency: Chrome's log list, each log's own signed tree head, and consistency proofs.
// RFC 6962 logs serve JSON (get-sth, get-sth-consistency); static-ct (tiled) logs serve a signed-note checkpoint.
import { createHash, createPublicKey, verify } from 'node:crypto'

export const LOG_LIST = 'https://www.gstatic.com/ct/log_list/v3/log_list.json'
const b64 = s => Buffer.from(s, 'base64')
const sha256 = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest()

// Logs Chrome currently trusts ("usable"), both kinds, with the key each one signs with.
export function usableLogs(list) {
  const out = []
  for (const op of list.operators) {
    for (const l of op.logs ?? []) if (l.state?.usable) out.push({ kind: 'rfc6962', operator: op.name, name: l.description, url: l.url, key: l.key, logId: l.log_id })
    for (const l of op.tiled_logs ?? []) if (l.state?.usable) out.push({ kind: 'tiled', operator: op.name, name: l.description, url: l.monitoring_url, key: l.key, logId: l.log_id })
  }
  return out
}

// The bytes a log signs for a tree head (RFC 6962 section 3.5, TreeHeadSignature).
export function treeHeadSignedBytes({ timestamp, treeSize, rootHash }) {
  const b = Buffer.alloc(2 + 8 + 8 + 32)
  b[0] = 0 // v1
  b[1] = 1 // tree_hash
  b.writeBigUInt64BE(BigInt(timestamp), 2)
  b.writeBigUInt64BE(BigInt(treeSize), 10)
  rootHash.copy(b, 18)
  return b
}

// A TLS DigitallySigned struct: hash alg, signature alg, 2-byte length, signature.
function digitallySigned(buf) {
  const len = buf.readUInt16BE(2)
  if (buf.length !== 4 + len) throw new Error('malformed DigitallySigned')
  return { hashAlg: buf[0], sigAlg: buf[1], sig: buf.subarray(4) }
}

// Both kinds end in the same check: the log's key over the TreeHeadSignature bytes, so a third party holding only
// (timestamp, size, root, DigitallySigned) and Chrome's log list can re-check a head.
export function logSignatureValid(keyB64, head) {
  try { return logKeyVerifies(keyB64, treeHeadSignedBytes(head), digitallySigned(head.logSignature)) } catch { return false }
}

function logKeyVerifies(keyB64, data, ds) {
  if (ds.hashAlg !== 4) return false // sha256, the only hash CT allows
  return verify('sha256', data, createPublicKey({ key: b64(keyB64), format: 'der', type: 'spki' }), ds.sig)
}

// RFC 6962: the JSON a log returns from get-sth, checked against the log's key.
export function parseSth(log, json) {
  const head = { log: log.name, kind: log.kind, treeSize: Number(json.tree_size), timestamp: Number(json.timestamp), rootHash: b64(json.sha256_root_hash) }
  head.logSignature = b64(json.tree_head_signature)
  head.valid = logSignatureValid(log.key, head)
  return head
}

// static-ct-api: a signed note whose log signature is an RFC 6962 TreeHeadSignature with the timestamp carried
// in the note signature: key ID (4) || timestamp (8) || DigitallySigned.
// The key ID is SHA-256(origin || "\n" || 0x05 || logID)[:4], where logID = SHA-256(SPKI); checked against live logs.
export function staticKeyId(origin, keyB64) {
  return sha256(Buffer.from(origin + '\n'), Buffer.from([0x05]), sha256(b64(keyB64))).subarray(0, 4)
}

export function parseCheckpoint(log, text) {
  const [body, sigs] = text.split('\n\n')
  const [origin, size, root] = body.split('\n')
  const head = { log: log.name, kind: log.kind, origin, treeSize: Number(size), rootHash: b64(root), timestamp: null, valid: false, note: body + '\n' }
  const keyId = staticKeyId(origin, log.key)
  for (const line of (sigs ?? '').split('\n')) {
    const m = line.match(/^— (\S+) (\S+)$/)
    if (!m || m[1] !== origin) continue
    const blob = b64(m[2])
    if (!blob.subarray(0, 4).equals(keyId)) continue // another signer, e.g. a witness cosignature
    head.timestamp = Number(blob.readBigUInt64BE(4))
    head.logSignature = blob.subarray(12)
    head.valid = logSignatureValid(log.key, head)
    head.otherSignatures = (sigs.match(/^— /gm) ?? []).length - 1
  }
  return head
}

// RFC 9162 section 2.1.4.2: does the tree of size `second` extend the tree of size `first`?
const node = (l, r) => sha256(Buffer.from([1]), l, r)
export function verifyConsistency(first, second, firstHash, secondHash, proof) {
  if (first > second) return false
  if (first === second) return proof.length === 0 && firstHash.equals(secondHash)
  if (first === 0) return proof.length === 0 // the empty tree is a prefix of every tree
  let path = [...proof]
  if ((first & (first - 1)) === 0) path.unshift(firstHash) // first is a power of two: its root is a node of the larger tree
  if (path.length === 0) return false
  let fn = BigInt(first - 1), sn = BigInt(second - 1)
  while (fn & 1n) { fn >>= 1n; sn >>= 1n }
  let fr = path[0], sr = path[0]
  for (const c of path.slice(1)) {
    if (sn === 0n) return false
    if ((fn & 1n) || fn === sn) {
      fr = node(c, fr); sr = node(c, sr)
      if (!(fn & 1n)) while (!(fn & 1n) && fn !== 0n) { fn >>= 1n; sn >>= 1n }
    } else {
      sr = node(sr, c)
    }
    fn >>= 1n; sn >>= 1n
  }
  return sn === 0n && fr.equals(firstHash) && sr.equals(secondHash)
}

// Live reads. Every caller decides what to do with an invalid or unreachable log; nothing here throws on a bad log.
const UA = { 'user-agent': 'treerings/0.1 (+https://github.com/SudeepGowda55/treerings)' }
const getJson = (url) => fetch(url, { headers: UA, signal: AbortSignal.timeout(15000) }).then(r => { if (!r.ok) throw new Error(`${r.status} ${url}`); return r.json() })
const getText = (url) => fetch(url, { headers: UA, signal: AbortSignal.timeout(15000) }).then(r => { if (!r.ok) throw new Error(`${r.status} ${url}`); return r.text() })

export async function fetchHead(log) {
  if (log.kind === 'rfc6962') return parseSth(log, await getJson(new URL('ct/v1/get-sth', log.url)))
  return parseCheckpoint(log, await getText(new URL('checkpoint', log.url)))
}

export async function fetchConsistency(log, first, second) {
  const j = await getJson(new URL(`ct/v1/get-sth-consistency?first=${first}&second=${second}`, log.url))
  return (j.consistency ?? []).map(b64)
}
