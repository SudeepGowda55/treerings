// The domain owner's side. `seal <domain...>` seals a watchlist to the witness and posts it to the rollup inbox;
// `alerts` reads the rollup inbox and opens the alerts the witness sealed to this account. Env: OWNER_MNEMONIC.
import { readFileSync } from 'node:fs'
import { fetchQledgerEntries } from '@qorechain/rdk'
import { connectRdk, ROLLUP_ID, CHAIN_ID } from '../src/rollup.js'
import { sealWatchlist, openAlert, sealKeys } from '../src/watchlist.js'

const dep = JSON.parse(readFileSync(new URL('../deployments/testnet.json', import.meta.url)))
const rdk = await connectRdk(process.env.OWNER_MNEMONIC)
const [cmd, ...domains] = process.argv.slice(2)

if (cmd === 'seal') {
  const data = await sealWatchlist({ rest: rdk.restUrl, chainId: CHAIN_ID, owner: rdk.address, witness: dep.rollup.operator, domains })
  const r = await rdk.tx.postRollupData({ rollupId: ROLLUP_ID, data })
  console.log(`sealed ${domains.length} names (${data.length} bytes on chain, none of them readable) -> ${r.transactionHash}`)
} else if (cmd === 'alerts') {
  const head = (await rdk.rest.getInbox(ROLLUP_ID)).headSequence
  const keys = sealKeys(process.env.OWNER_MNEMONIC)
  const entries = await fetchQledgerEntries(rdk.rest, { chainId: CHAIN_ID, rollupId: ROLLUP_ID, from: 0, to: head, accFrom: '00'.repeat(32) })
  for (const e of entries) {
    if (e.poster !== dep.rollup.operator) continue
    const a = openAlert({ chainId: CHAIN_ID, keys, owner: rdk.address, data: Buffer.from(e.payload) })
    if (a) for (const h of a.hits) console.log(`${new Date(h.loggedAt).toISOString()}  ${h.name}  (${h.log} #${h.index}${h.precert ? ', precert' : ''})`)
  }
}
process.exit(0)
