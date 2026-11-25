// The L2 round trip from any account: `deposit` credits an L2 ledger account and posts a signed qledger-v1
// withdrawal back to this account; once the batch that carries it is finalized, `pay` proves it from the
// watchtower's own replay of the inbox and the chain pays it out of the rollup's deposit pool.
// Env: WATCHTOWER_MNEMONIC, L2_SEED (hex 32 bytes).
import { qledgerKeypairFromSeed, signQledgerTx, encodeQledgerTx, qledgerWithdrawalProof, bytesToHex } from '@qorechain/rdk'
import { connectRdk, ROLLUP_ID, CHAIN_ID } from '../src/rollup.js'
import { createWatchtower } from '../src/watchtower.js'
import { readFileSync } from 'node:fs'

const QOR = 1_000_000n
const rdk = await connectRdk(process.env.WATCHTOWER_MNEMONIC)
const l2 = qledgerKeypairFromSeed(process.env.L2_SEED)
console.log('L1 account', rdk.address, '| L2 account', bytesToHex(l2.accountId))

if (process.argv[2] === 'deposit') {
  console.log('deposit 2 QOR ->', (await rdk.tx.depositToRollup({ rollupId: ROLLUP_ID, account: l2.accountId, amount: 2n * QOR })).transactionHash)
  const tx = signQledgerTx({ chainId: CHAIN_ID, rollupId: ROLLUP_ID, ...l2, nonce: 0, amount: QOR, recipient: rdk.address })
  console.log('post withdrawal of 1 QOR ->', (await rdk.tx.postRollupData({ rollupId: ROLLUP_ID, data: encodeQledgerTx(tx) })).transactionHash)
} else if (process.argv[2] === 'pay') {
  const dep = JSON.parse(readFileSync(new URL('../deployments/testnet.json', import.meta.url)))
  const tower = createWatchtower({ rest: rdk.rest, chainId: CHAIN_ID, rollupId: ROLLUP_ID, operator: dep.rollup.operator, witnessName: dep.witness, witnessKey: Buffer.alloc(2592) })
  await tower.poll()
  for (const b of tower.report.withdrawals) {
    const i = b.all.findIndex(w => w.recipient === rdk.address)
    if (i < 0) continue
    const w = b.all[i]
    const status = (await rdk.rest.getBatch(ROLLUP_ID, b.batchIndex)).status
    console.log(`withdrawal #${w.index} of ${Number(w.amount) / 1e6} QOR in batch ${b.batchIndex} (${status})`)
    if (status !== 'finalized') { console.log('not final yet; the challenge window is one hour'); break }
    const r = await rdk.tx.executeWithdrawal({ rollupId: ROLLUP_ID, batchIndex: b.batchIndex, withdrawalIndex: w.index, recipient: w.recipient, denom: 'uqor', amount: w.amount, proof: qledgerWithdrawalProof(CHAIN_ID, ROLLUP_ID, b.all, i) })
    console.log('paid ->', r.transactionHash)
  }
}
process.exit(0)
