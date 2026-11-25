import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateSealKeys } from '@qorechain/qoreseal'
import { sealWatchlist, openWatchlist, sealAlert, openAlert, matches } from '../src/watchlist.js'

const chainId = 'qorechain-diana'
const witness = generateSealKeys(), owner = generateSealKeys()
// stands in for GET /qorechain/pqc/v1/kem/{address}
const keyOf = { 'qor1witness': witness, 'qor1owner': owner }
const fakeRest = 'https://kem.test'
globalThis.fetch = async url => {
  const addr = String(url).split('/').pop()
  return new Response(JSON.stringify({ found: true, key: { address: addr, algorithm_id: 2, algorithm_name: 'ml-kem-1024', public_key: Buffer.from(keyOf[addr].mlkemPublicKey).toString('base64') } }), { headers: { 'content-type': 'application/json' } })
}

test('a sealed watchlist opens only for the witness, and only from the account that posted it', async () => {
  let data
  try { data = await sealWatchlist({ rest: fakeRest, chainId, owner: 'qor1owner', witness: 'qor1witness', domains: ['example.com'] }) } catch (e) { return assert.fail(`KEM lookup shape: ${e.message}`) }
  assert.equal(data.includes(Buffer.from('example.com')), false)
  assert.deepEqual(openWatchlist({ chainId, keys: witness, poster: 'qor1owner', data }), { owner: 'qor1owner', domains: ['example.com'] })
  assert.equal(openWatchlist({ chainId, keys: witness, poster: 'qor1copycat', data }), undefined)
  assert.equal(openWatchlist({ chainId, keys: owner, poster: 'qor1owner', data }), undefined)
  const alert = await sealAlert({ rest: fakeRest, chainId, owner: 'qor1owner', hits: [{ name: 'a.example.com' }] })
  assert.deepEqual(openAlert({ chainId, keys: owner, owner: 'qor1owner', data: alert }), { hits: [{ name: 'a.example.com' }] })
})

test('domain matching covers subdomains and wildcards, not look-alikes', () => {
  assert.ok(matches('example.com', 'example.com'))
  assert.ok(matches('a.b.example.com', 'example.com'))
  assert.ok(matches('*.example.com', 'example.com'))
  assert.equal(matches('badexample.com', 'example.com'), false)
  assert.equal(matches('example.com.evil.net', 'example.com'), false)
})
