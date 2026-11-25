// One-time: create the tree-rings rollup (custom profile, optimistic, based, qledger-v1) and bond the operator as
// its batch submitter. Simulates each message before sending it. Needs QORE_MNEMONIC.
import { createRollupMsg, bondRollupSubmitterMsg, rollupModeErrors, isRestNotFound } from '@qorechain/rdk'
import { connectRdk, ROLLUP_ID } from '../src/rollup.js'

const SEND = process.argv.includes('--send')
const { tx, rest, address } = await connectRdk(process.env.QORE_MNEMONIC)
const params = await rest.getParams()
const mode = { settlement: 'optimistic', proofSystem: 'fraud', sequencing: 'based', executionVm: 'qledger-v1', privacy: '' }
console.log('mode errors:', rollupModeErrors(mode))

let exists = true
try { await rest.getRollup(ROLLUP_ID) } catch (e) { if (isRestNotFound(e) || /501|Not Implemented|not found/i.test(e.message)) exists = false; else throw e }
const listed = (await fetch(`https://api-testnet.qore.host/qorechain/rdk/v1/rollups`).then(r => r.json())).rollups.some(r => r.rollup_id === ROLLUP_ID)
console.log('exists:', exists, 'listed:', listed, 'stake:', params.minStakeForRollup)

if (!listed) {
  const input = { rollupId: ROLLUP_ID, profile: 'custom', vmType: 'custom', stakeAmount: params.minStakeForRollup, sequencing: 'based', executionVm: 'qledger-v1' }
  console.log('create simulate gas:', await tx.simulate([createRollupMsg({ creator: address, ...input })]))
  if (SEND) console.log('created:', (await tx.createRollup(input)).transactionHash)
}
const bond = await rest.getSubmitterBond(ROLLUP_ID, address).catch(() => ({ amount: '0' }))
if (BigInt(bond.amount ?? 0) < BigInt(params.minSubmitterBond ?? '1000000000') && (listed || SEND)) {
  const msg = bondRollupSubmitterMsg({ submitter: address, rollupId: ROLLUP_ID, amount: params.minSubmitterBond ?? '1000000000' })
  console.log('bond simulate gas:', await tx.simulate([msg]))
  if (SEND) console.log('bonded:', (await tx.bondRollupSubmitter({ rollupId: ROLLUP_ID, amount: params.minSubmitterBond ?? '1000000000' })).transactionHash)
}
process.exit(0)
