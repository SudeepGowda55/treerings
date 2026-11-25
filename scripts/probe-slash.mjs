// Read-only: simulates slashSplitView against the live WitnessBond with two real ML-DSA-87 cosignatures, so the
// chain's own pqcVerify precompile judges them. A real split view passes; two signatures of one head do not.
import { readFileSync } from 'node:fs'
import { createPublicClient, http, defineChain } from 'viem'
import { createHash } from 'node:crypto'
import { EVM_RPC } from '../src/chain.js'
import { witnessFromSeed, cosign } from '../src/cosign.js'

const dep = JSON.parse(readFileSync(new URL('../deployments/testnet.json', import.meta.url)))
const { abi } = JSON.parse(readFileSync(new URL('../contracts/out/WitnessBond.sol/WitnessBond.json', import.meta.url)))
const chain = defineChain({ id: 9800, name: 'qorechain-diana', nativeCurrency: { name: 'QOR', symbol: 'QOR', decimals: 18 }, rpcUrls: { default: { http: [EVM_RPC] } } })
const pub = createPublicClient({ chain, transport: http() })
const w = witnessFromSeed(dep.witness, Buffer.from(process.env.WITNESS_SEED, 'hex'))
const url = 'https://ct.cloudflare.com/logs/nimbus2026/'
const h = s => createHash('sha256').update(s).digest()
const toCosig = c => ({ timestamp: BigInt(c.timestamp), treeSize: BigInt(c.treeSize), root: `0x${c.rootHash.toString('hex')}`, signature: `0x${c.signature.toString('hex')}` })
const origin = 'ct.cloudflare.com/logs/nimbus2026'
const a = toCosig(cosign(w, { url, treeSize: 1000, rootHash: h('A') }, 1800000000))
const b = toCosig(cosign(w, { url, treeSize: 1000, rootHash: h('B') }, 1800000001))
const a2 = toCosig(cosign(w, { url, treeSize: 1000, rootHash: h('A') }, 1800000002))
const sim = args => pub.simulateContract({ address: dep.witnessBond, abi, functionName: 'slashSplitView', args, account: '0x000000000000000000000000000000000000dEaD' })
  .then(() => 'would slash').catch(e => e.cause?.data?.errorName ?? e.shortMessage)
console.log('split view          :', await sim([dep.witness, origin, a, b]))
console.log('same head, re-signed:', await sim([dep.witness, origin, a, a2]))
console.log('tampered signature  :', await sim([dep.witness, origin, a, { ...b, root: `0x${h('C').toString('hex')}` }]))
