import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { parseCheckpoint, verifyConsistency } from '../src/ct.js'
import { makeTileReader, tilePath } from '../src/tiles.js'

test('tile paths follow c2sp tlog-tiles', () => {
  assert.equal(tilePath(0, 1234067), 'tile/0/x001/x234/067')
  assert.equal(tilePath(2, 5, 17), 'tile/2/005.p/17')
  assert.equal(tilePath(1, 0), 'tile/1/000')
})

test("a real tiled log: root and consistency proof rebuilt from its own tiles match its two signed checkpoints", async () => {
  const f = JSON.parse(readFileSync(new URL('./fixtures/tuscolo2026h2-tiles.json', import.meta.url)))
  const a = parseCheckpoint(f.log, f.first), b = parseCheckpoint(f.log, f.second)
  assert.ok(a.valid && b.valid, "both checkpoints carry the log's own valid signature")
  const fromFixture = async url => {
    const t = f.tiles[new URL(url).pathname]
    if (!t) throw new Error(`tile not recorded: ${url}`)
    return Buffer.from(t, 'base64')
  }
  const rd = makeTileReader(f.log.url, b.treeSize, fromFixture)
  assert.ok((await rd.root()).equals(b.rootHash))
  const proof = await rd.consistency(a.treeSize)
  assert.ok(verifyConsistency(a.treeSize, b.treeSize, a.rootHash, b.rootHash, proof))
  // the same proof cannot make the old head fit a different new root
  assert.equal(verifyConsistency(a.treeSize, b.treeSize, a.rootHash, Buffer.alloc(32), proof), false)
})
