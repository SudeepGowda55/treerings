// One witness cosignature as one rollup inbox post (qledger-v1 caps a post at 6 KiB and treats non-ledger bytes
// as a no-op). Everything a third party needs to re-check both signatures is in the post:
//   "TRC1" | logId(32) | u8 len, origin | u64 treeSize | root(32) | u64 logTimestamp(ms)
//   | u16 len, log DigitallySigned | u64 witnessTimestamp(s) | ML-DSA-87 signature(4627)
const MAGIC = Buffer.from('TRC1')
export const MAX_POST = 6 * 1024

const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b }

export function encodePost({ logId, origin, treeSize, rootHash, logTimestamp, logSignature, witnessTimestamp, signature }) {
  const o = Buffer.from(origin)
  const ls = Buffer.alloc(2); ls.writeUInt16BE(logSignature.length)
  const out = Buffer.concat([MAGIC, Buffer.from(logId, 'base64'), Buffer.from([o.length]), o, u64(treeSize), rootHash, u64(logTimestamp), ls, logSignature, u64(witnessTimestamp), signature])
  if (logId && Buffer.from(logId, 'base64').length !== 32) throw new Error('logId must be 32 bytes')
  if (out.length > MAX_POST) throw new Error(`post is ${out.length} bytes, over ${MAX_POST}`)
  return out
}

// Returns undefined for anything that is not a Tree Rings post: the inbox of a based rollup is open to everyone.
export function decodePost(buf) {
  try {
    buf = Buffer.from(buf)
    if (!buf.subarray(0, 4).equals(MAGIC)) return undefined
    let i = 4
    const logId = buf.subarray(i, i += 32).toString('base64')
    const ol = buf[i++]; const origin = buf.subarray(i, i += ol).toString()
    const treeSize = Number(buf.readBigUInt64BE(i)); i += 8
    const rootHash = buf.subarray(i, i += 32)
    const logTimestamp = Number(buf.readBigUInt64BE(i)); i += 8
    const sl = buf.readUInt16BE(i); i += 2
    const logSignature = buf.subarray(i, i += sl)
    const witnessTimestamp = Number(buf.readBigUInt64BE(i)); i += 8
    const signature = buf.subarray(i)
    if (signature.length !== 4627) return undefined
    return { logId, origin, treeSize, rootHash, logTimestamp, logSignature, witnessTimestamp, signature }
  } catch { return undefined }
}
