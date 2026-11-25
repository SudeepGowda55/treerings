// Publish this account's ML-KEM-1024 key (QoreSeal, derived from the mnemonic) in the chain's KEM registry,
// so others can seal to it. Env: MNEMONIC.
import { fetchKemKey } from '@qorechain/qoreseal/network'
import { connectRdk } from '../src/rollup.js'
import { sealKeys } from '../src/watchlist.js'

const rdk = await connectRdk(process.env.MNEMONIC)
const keys = sealKeys(process.env.MNEMONIC)
const st = await fetchKemKey({ rest: rdk.restUrl, address: rdk.address })
if (st.registered && Buffer.from(st.publicKey).equals(Buffer.from(keys.mlkemPublicKey))) console.log(rdk.address, 'already registered')
else console.log(rdk.address, 'registered ->', (await rdk.tx.registerKemKey({ publicKey: keys.mlkemPublicKey })).transactionHash)
process.exit(0)
