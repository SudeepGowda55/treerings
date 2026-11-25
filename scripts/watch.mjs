// Runs the witness: a round over every usable log each ROUND_MIN minutes, a batch each BATCH_MIN minutes.
// Env: QORE_MNEMONIC, WITNESS_SEED; optional EVERY_HOURS (per-log cosign interval), MAX_POSTS (per round), ONCE=1.
import { connectRdk } from '../src/rollup.js'
import { witnessFromSeed } from '../src/cosign.js'
import { round, settle, load } from '../src/watcher.js'

const ROUND_MIN = Number(process.env.ROUND_MIN ?? 10), BATCH_MIN = Number(process.env.BATCH_MIN ?? 30)
const everyMs = Number(process.env.EVERY_HOURS ?? 6) * 3600e3, maxPosts = Number(process.env.MAX_POSTS ?? 4)
const say = m => console.log(new Date().toISOString(), m)
const rdk = await connectRdk(process.env.QORE_MNEMONIC)
const witness = witnessFromSeed('treerings.witness/1', Buffer.from(process.env.WITNESS_SEED, 'hex'))
const state = load()
for (;;) {
  try {
    const r = await round({ rdk, witness, state, everyMs, maxPosts, log: say })
    say(`round: ${r.checked}/${r.logs} logs verified, ${r.posted} cosigned`)
    if (Date.now() - state.lastBatchAt > BATCH_MIN * 60e3) await settle({ rdk, state, say })
  } catch (e) { say(`round failed: ${e.stack ?? e}`) }
  if (process.env.ONCE) break
  await new Promise(r => setTimeout(r, ROUND_MIN * 60e3))
}
process.exit(0)
