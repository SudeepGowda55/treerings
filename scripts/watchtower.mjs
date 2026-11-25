// Run the watchtower from any funded, PQC-registered account. Env: WATCHTOWER_MNEMONIC; CHALLENGE=1 to challenge
// fraud it finds (posts the rollup's challenge bond); ONCE=1 for a single audit.
import { readFileSync } from 'node:fs'
import { createPublicClient, http, defineChain } from 'viem'
import { connectRdk, ROLLUP_ID, CHAIN_ID } from '../src/rollup.js'
import { createWatchtower } from '../src/watchtower.js'
import { EVM_RPC } from '../src/chain.js'

const dep = JSON.parse(readFileSync(new URL('../deployments/testnet.json', import.meta.url)))
const { abi } = JSON.parse(readFileSync(new URL('../contracts/out/WitnessBond.sol/WitnessBond.json', import.meta.url)))
const chain = defineChain({ id: 9800, name: 'qorechain-diana', nativeCurrency: { name: 'QOR', symbol: 'QOR', decimals: 18 }, rpcUrls: { default: { http: [EVM_RPC] } } })
const say = m => console.log(new Date().toISOString(), m)

// The witness key comes from the bond contract, not from the operator.
const [, pubkey, bond] = await createPublicClient({ chain, transport: http() }).readContract({ address: dep.witnessBond, abi, functionName: 'witness', args: [dep.witness] })
say(`witness ${dep.witness}: ${(pubkey.length - 2) / 2}-byte ML-DSA-87 key, bond ${Number(bond) / 1e18} QOR`)
const rdk = await connectRdk(process.env.WATCHTOWER_MNEMONIC)
say(`watchtower account ${rdk.address}`)
const tower = createWatchtower({ rest: rdk.rest, chainId: CHAIN_ID, rollupId: ROLLUP_ID, operator: dep.rollup.operator, witnessName: dep.witness, witnessKey: Buffer.from(pubkey.slice(2), 'hex') })

for (;;) {
  try {
    for (const f of await tower.poll()) {
      say(`FRAUD in batch ${f.batchIndex}: published root ${f.published}, re-execution gives ${f.honest}`)
      if (process.env.CHALLENGE) say(`challenged -> ${(await rdk.tx.challengeBatch({ rollupId: ROLLUP_ID, batchIndex: f.batchIndex, proof: f.proof })).transactionHash}`)
    }
    const r = tower.report
    say(`audited ${r.batches} batches: ${r.verified}/${r.posts} cosignatures verified, ${r.bad.length} bad, ${r.splitViews.length} split views, ${r.foreign} foreign posts, ${r.fraud.length} fraudulent batches`)
  } catch (e) { say(`audit failed: ${e.stack ?? e}`) }
  if (process.env.ONCE) break
  await new Promise(r => setTimeout(r, 60e3))
}
process.exit(0)
