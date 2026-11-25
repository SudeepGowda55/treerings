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
import { planQledgerBatch, QledgerLedger, hexToBytes, fetchQledgerEntries } from '@qorechain/rdk'
import { newestEntries, dnsNames } from './certs.js'
import { openWatchlist, sealAlert, matches } from './watchlist.js'

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

// Sealed watchlists: read new inbox posts, open the lists sealed to this witness, then check the newest
// certificates of a few tiled logs against them and seal each owner's hits back to them as one post.
export async function scanWatchlists({ rdk, sealKeys, state, logsPerRound = 6, say = console.log }) {
  const wl = (state.wl ??= { seq: 0, acc: '00'.repeat(32), lists: {}, seen: {}, cursor: 0, alerts: [] })
  const head = (await rdk.rest.getInbox(ROLLUP_ID)).headSequence
  if (head > wl.seq) {
    const entries = await fetchQledgerEntries(rdk.rest, { chainId: CHAIN_ID, rollupId: ROLLUP_ID, from: wl.seq, to: head, accFrom: wl.acc })
    for (const e of entries) {
      const list = openWatchlist({ chainId: CHAIN_ID, keys: sealKeys, poster: e.poster, data: Buffer.from(e.payload) })
      if (list) { wl.lists[e.poster] = list.domains; say(`watchlist from ${e.poster}: ${list.domains.length} names (sealed)`) }
    }
    wl.acc = (await rdk.rest.getPostedData(ROLLUP_ID, head)).inboxAcc
    wl.seq = head
  }
  const owners = Object.keys(wl.lists)
  if (!owners.length) return
  const list = await fetch(LOG_LIST, { headers: { 'user-agent': USER_AGENT } }).then(r => r.json())
  const tiled = usableLogs(list).filter(l => l.kind === 'tiled')
  const hits = {}
  for (let k = 0; k < Math.min(logsPerRound, tiled.length); k++) {
    const log = tiled[(wl.cursor + k) % tiled.length]
    try {
      const head = await fetchHead(log)
      if (!head.valid) continue
      const { first, entries } = await newestEntries(log.url, head.treeSize)
      entries.forEach((e, i) => {
        const names = dnsNames(e.der)
        for (const owner of owners) {
          const name = names.find(n => wl.lists[owner].some(d => matches(n, d)))
          const key = `${log.logId}:${first + i}`
          if (name && !wl.seen[key]) { wl.seen[key] = 1; (hits[owner] ??= []).push({ name, log: log.name, index: first + i, precert: e.precert, loggedAt: e.timestamp }) }
        }
      })
    } catch (e) { say(`watchlist scan ${log.name}: ${e.message}`) }
  }
  wl.cursor = (wl.cursor + logsPerRound) % tiled.length
  for (const [owner, h] of Object.entries(hits)) {
    const data = await sealAlert({ rest: rdk.restUrl, chainId: CHAIN_ID, owner, hits: h.slice(0, 15) /* a post is capped at 6 KiB */ })
    const r = await rdk.tx.postRollupData({ rollupId: ROLLUP_ID, data })
    wl.alerts.push({ owner, count: h.length, tx: r.transactionHash, at: Date.now() })
    say(`sealed alert to ${owner}: ${h.length} new certificates -> ${r.transactionHash}`)
  }
  save(state)
}

export { load, save }
