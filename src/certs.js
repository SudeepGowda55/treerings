// Certificates from a static-ct (tiled) log's data tiles, with their DNS names. Each TileLeaf is a
// TimestampedEntry (an X.509 cert, or a precert's TBS) followed, for precerts, by the full pre-certificate,
// then the chain fingerprints; the pre-certificate parses as an ordinary certificate.
import { X509Certificate } from 'node:crypto'
import { defaultFetch, tilePath } from './tiles.js'

const u24 = (b, i) => (b[i] << 16) | (b[i + 1] << 8) | b[i + 2]

export function parseDataTile(buf) {
  const out = []
  let i = 0
  while (i < buf.length) {
    const timestamp = Number(buf.readBigUInt64BE(i)); i += 8
    const type = buf.readUInt16BE(i); i += 2
    let der
    if (type === 0) { const n = u24(buf, i); der = buf.subarray(i + 3, i + 3 + n); i += 3 + n }
    else if (type === 1) { i += 32; i += 3 + u24(buf, i) } else throw new Error(`entry type ${type}`)
    i += 2 + buf.readUInt16BE(i) // extensions
    if (type === 1) { const n = u24(buf, i); der = buf.subarray(i + 3, i + 3 + n); i += 3 + n }
    i += 2 + buf.readUInt16BE(i) // chain fingerprints
    out.push({ timestamp, precert: type === 1, der })
  }
  return out
}

export function dnsNames(der) {
  try {
    const c = new X509Certificate(der)
    return (c.subjectAltName ?? '').split(', ').filter(s => s.startsWith('DNS:')).map(s => s.slice(4).toLowerCase())
  } catch { return [] }
}

// The newest complete data tile of a tiled log of `treeSize` entries: 256 entries starting at `first`.
// shortcut: samples one tile per log per round; watching every entry needs a follower that walks every new tile.
export async function newestEntries(baseUrl, treeSize, fetchBytes = defaultFetch) {
  const n = Math.floor(treeSize / 256) - 1
  if (n < 0) return { first: 0, entries: [] }
  return { first: n * 256, entries: parseDataTile(await fetchBytes(new URL(tilePath('data', n), baseUrl))) }
}
