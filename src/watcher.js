// The live witness. Every round it reads every log Chrome trusts and checks each new head's own signature. When a
// log is due, it also proves the head extends the last one this witness cosigned (RFC 9162 consistency), cosigns
// it with ML-DSA-87 and posts the cosignature to the tree-rings rollup inbox. Batches settle the inbox on QoreChain.
// Heads that fail a check are never cosigned; they are kept as evidence instead.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { usableLogs, fetchHead, fetchConsistency, verifyConsistency, LOG_LIST } from './ct.js'
import { makeTileReader, USER_AGENT } from './tiles.js'
import { cosign, originOf } from './cosign.js'
import { encodePost } from './post.js'
import { ROLLUP_ID, CHAIN_ID } from './rollup.js'
import { planQledgerBatch, QledgerLedger, hexToBytes } from '@qorechain/rdk'

const STATE = new URL('../state/watcher.json', import.meta.url)
const load = () => { try { return JSON.parse(readFileSync(STATE)) } catch { return { heads: {}, refused: [], ledger: [], lastBatchAt: 0 } } }
const save = s => { mkdirSync(new URL('../state/', import.meta.url), { recursive: true }); writeFileSync(STATE, JSON.stringify(s, null, 1)) }

// Is `head` an honest extension of the head we cosigned before? A first sighting has nothing to extend.
async function extendsPrevious(log, prev, head) {
  if (!prev) return true
  if (head.treeSize < prev.treeSize) return false
  if (head.treeSize === prev.treeSize) return Buffer.from(prev.rootHash, 'hex').equals(head.rootHash)
  const proof = log.kind === 'rfc6962'
    ? await fetchConsistency(log, prev.treeSize, head.treeSize)
    : await makeTileReader(log.url, head.treeSize).consistency(prev.treeSize)
  return verifyConsistency(prev.treeSize, head.treeSize, Buffer.from(prev.rootHash, 'hex'), head.rootHash, proof)
}

export async function round({ rdk, witness, state, everyMs, maxPosts, log: say = console.log }) {
  const list = await fetch(LOG_LIST, { headers: { 'user-agent': USER_AGENT } }).then(r => r.json())
  const logs = usableLogs(list)
  // most overdue first, so a post cap rotates fairly through the logs
  logs.sort((a, b) => (state.heads[a.logId]?.postedAt ?? 0) - (state.heads[b.logId]?.postedAt ?? 0))
  let checked = 0, posted = 0
  for (const log of logs) {
    let head
    try { head = await fetchHead(log) } catch (e) { say(`skip ${log.name}: ${e.message}`); continue }
    checked++
    if (!head.valid) { state.refused.push({ log: log.name, at: Date.now(), why: 'log signature', treeSize: head.treeSize }); say(`REFUSED ${log.name}: bad log signature`); continue }
    const prev = state.heads[log.logId]
    if (posted >= maxPosts || (prev && Date.now() - prev.postedAt < everyMs)) continue
    let ok
    try { ok = await extendsPrevious(log, prev, head) } catch (e) { say(`skip ${log.name}: proof ${e.message}`); continue }
    if (!ok) { state.refused.push({ log: log.name, at: Date.now(), why: 'not consistent with the last cosigned head', from: prev.treeSize, to: head.treeSize }); say(`REFUSED ${log.name}: inconsistent`); continue }
    const c = cosign(witness, { ...head, url: log.url })
    const data = encodePost({ logId: log.logId, origin: originOf({ ...head, url: log.url }), treeSize: head.treeSize, rootHash: head.rootHash, logTimestamp: head.timestamp, logSignature: head.logSignature, witnessTimestamp: c.timestamp, signature: c.signature })
    const r = await rdk.tx.postRollupData({ rollupId: ROLLUP_ID, data })
    state.heads[log.logId] = { log: log.name, treeSize: head.treeSize, rootHash: head.rootHash.toString('hex'), postedAt: Date.now(), tx: r.transactionHash }
    save(state)
    posted++
    say(`cosigned ${log.name} @ ${head.treeSize} -> ${r.transactionHash}`)
  }
  return { checked, posted, logs: logs.length }
}

// Settle whatever the inbox holds. The ledger (deposits, withdrawals) is kept locally between batches and checked
// against the chain's latest state root by planQledgerBatch, which refuses a mismatch.
export async function settle({ rdk, state, say = console.log }) {
  const ledger = new QledgerLedger()
  for (const a of state.ledger) ledger.set(hexToBytes(a.id), BigInt(a.balance), BigInt(a.nonce))
  let plan
  try { plan = await planQledgerBatch(rdk.rest, { chainId: CHAIN_ID, rollupId: ROLLUP_ID, submitter: rdk.address, ledger }) } catch (e) { say(`no batch: ${e.message}`); return }
  const r = await rdk.tx.submitBatch(plan.input)
  state.ledger = plan.ledger.accounts().map(a => ({ id: Buffer.from(a.id).toString('hex'), balance: String(a.balance), nonce: String(a.nonce) }))
  state.lastBatchAt = Date.now()
  ;(state.batches ??= []).push({ index: String(plan.input.batchIndex), inboxEnd: String(plan.input.inboxEnd), tx: r.transactionHash, withdrawals: plan.result.withdrawals.map(w => ({ ...w, amount: String(w.amount), index: String(w.index ?? '') })) })
  save(state)
  say(`batch ${plan.input.batchIndex} (inbox to ${plan.input.inboxEnd}, ${plan.entries.length} posts) -> ${r.transactionHash}`)
  return plan
}

export { load, save }
