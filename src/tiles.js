// Consistency proofs for static-ct (tiled) logs, built from the log's public hash tiles (c2sp tlog-tiles).
// A tile at level L holds up to 256 hashes of the tree's nodes at height 8L; anything between is hashed locally.
import { createHash } from 'node:crypto'

const H = (...p) => createHash('sha256').update(Buffer.concat(p)).digest()
const node = (l, r) => H(Buffer.from([1]), l, r)
const W = 256

// Tile index N as path segments: x001/x234/067 (every segment but the last gets an "x").
export function tilePath(level, index, width = W) {
  const digits = String(index).padStart(3, '0')
  const parts = []
  for (let s = digits; s.length; s = s.slice(0, -3)) parts.unshift(s.slice(-3).padStart(3, '0'))
  const p = parts.map((d, i) => (i < parts.length - 1 ? 'x' + d : d)).join('/')
  return `tile/${level}/${p}${width < W ? `.p/${width}` : ''}`
}

export function makeTileReader(baseUrl, treeSize, fetchBytes = defaultFetch) {
  const cache = new Map()
  // Hashes stored at height 8L: how many exist in a tree of treeSize leaves.
  const rowWidth = L => Math.floor(treeSize / 2 ** (8 * L))
  async function tile(L, n) {
    const width = Math.min(W, rowWidth(L) - n * W)
    const key = `${L}/${n}/${width}`
    if (!cache.has(key)) cache.set(key, fetchBytes(new URL(tilePath(L, n, width), baseUrl)).then(b => {
      if (b.length !== width * 32) throw new Error(`tile ${key}: ${b.length} bytes, expected ${width * 32}`)
      return b
    }))
    return cache.get(key)
  }
  // Root of the complete subtree of height h at index i (covers leaves i*2^h .. (i+1)*2^h - 1).
  async function nodeHash(h, i) {
    const L = Math.floor(h / 8), r = h % 8
    const start = i * 2 ** r, count = 2 ** r
    const t = await tile(L, Math.floor(start / W))
    let row = []
    for (let j = 0; j < count; j++) { const o = ((start + j) % W) * 32; row.push(t.subarray(o, o + 32)) }
    while (row.length > 1) { const next = []; for (let j = 0; j < row.length; j += 2) next.push(node(row[j], row[j + 1])); row = next }
    return row[0]
  }
  // Merkle tree hash of leaves [start, end): split at the largest power of two, as RFC 9162 defines it.
  async function rangeRoot(start, end) {
    const n = end - start
    if ((n & (n - 1)) === 0 && start % n === 0) return nodeHash(Math.log2(n), start / n)
    let k = 1; while (k * 2 < n) k *= 2
    return node(await rangeRoot(start, start + k), await rangeRoot(start + k, end))
  }
  // RFC 9162 SUBPROOF(m, D[start:end], complete)
  async function subproof(m, start, end, complete) {
    const n = end - start
    if (m === n) return complete ? [] : [await rangeRoot(start, end)]
    let k = 1; while (k * 2 < n) k *= 2
    if (m <= k) return [...await subproof(m, start, start + k, complete), await rangeRoot(start + k, end)]
    return [...await subproof(m - k, start + k, end, false), await rangeRoot(start, start + k)]
  }
  return {
    root: () => rangeRoot(0, treeSize),
    consistency: (oldSize) => (oldSize === treeSize || oldSize === 0 ? Promise.resolve([]) : subproof(oldSize, 0, treeSize, true)),
    fetched: () => cache.size,
  }
}

// Log operators ask monitors to identify themselves and to back off when told to.
export const USER_AGENT = 'treerings/0.1 (+https://github.com/SudeepGowda55/treerings)'
export async function defaultFetch(url, tries = 4) {
  for (let i = 0; ; i++) {
    const r = await fetch(url, { headers: { 'user-agent': USER_AGENT }, signal: AbortSignal.timeout(20000) })
    if (r.ok) return Buffer.from(await r.arrayBuffer())
    if ((r.status !== 429 && r.status < 500) || i + 1 >= tries) throw new Error(`${r.status} ${url}`)
    await new Promise(res => setTimeout(res, 1000 * Math.min(30, Number(r.headers.get('retry-after')) || 2 ** (i + 1))))
  }
}
