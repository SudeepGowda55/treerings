// The tree-rings rollup: a based, optimistic qledger-v1 rollup on qorechain-diana. Each witness cosignature is
// one inbox post (the ledger treats it as a no-op), so the chain orders and commits every cosignature in the
// batch's data_hash; the ledger itself only carries the deposit and withdrawal flow.
import { RdkTxClient, RestClient } from '@qorechain/rdk'
import { createClient, deriveNativeAccount, derivePqcCanonical, directSignerFromPrivateKey } from '@qorechain/sdk'
import { NETWORK } from './chain.js'

export const ROLLUP_ID = 'tree-rings'
export const CHAIN_ID = 'qorechain-diana'

export async function connectRdk(mnemonic) {
  const { endpoints } = createClient({ network: NETWORK }).network
  const acct = await deriveNativeAccount(mnemonic)
  const pqcKeypair = derivePqcCanonical(acct.address, mnemonic)
  const signer = await directSignerFromPrivateKey(acct.privateKey, 'qor')
  const tx = await RdkTxClient.connect(endpoints.rpc, signer, { pqcKeypair, rest: endpoints.rest, gasPrice: '0.15uqor' })
  return { tx, rest: new RestClient(endpoints.rest), restUrl: endpoints.rest, address: acct.address, pqcKeypair }
}
