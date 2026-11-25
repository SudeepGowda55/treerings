// The watchtower: anyone can run it from any funded account. It trusts nothing the operator says. It replays the
// rollup's inbox from the chain, re-executes every batch, and checks each cosignature post: the log's own
// signature, and the witness's ML-DSA-87 signature under the key bonded in WitnessBond. It also looks for two
// cosignatures that cannot both be honest. A batch whose roots are wrong gets a fraud proof the chain will accept.
import { executeQledger, fetchQledgerEntries, buildQledgerFraudProof, checkQledgerFraud, QledgerLedger, withdrawalsRootMatches, bytesToHex } from '@qorechain/rdk'
import { logSignatureValid, usableLogs, LOG_LIST } from './ct.js'
import { verifyCosignature } from './cosign.js'
import { decodePost } from './post.js'
import { USER_AGENT } from './tiles.js'

const ZERO = '00'.repeat(32)

export function createWatchtower({ rest, chainId, rollupId, operator, witnessName, witnessKey }) {
  const env = { chainId, rollupId }
  let ledger = new QledgerLedger()
  const seen = new Map() // origin|size -> post, to catch a split view
  const report = { batches: 0, posts: 0, verified: 0, foreign: 0, bad: [], splitViews: [], fraud: [] }
  let next = 0, logKeys
  const flagged = new Set()

  async function auditBatch(b) {
    const accFrom = b.inboxStart === 0 ? ZERO : (await rest.getPostedData(rollupId, b.inboxStart)).inboxAcc
    const entries = await fetchQledgerEntries(rest, { chainId, rollupId, from: b.inboxStart, to: b.inboxEnd, accFrom })
    const parent = ledger.clone()
    const honest = executeQledger(env, ledger, entries)
    const rootOk = bytesToHex(honest.stateRoot) === b.stateRoot.replace(/^0x/, '').toLowerCase()
    const wOk = honest.withdrawals.length === 0 ? !b.withdrawalsRoot : withdrawalsRootMatches(b.withdrawalsRoot, honest.withdrawalsRoot, b.withdrawalsRootReduced)
    let fraud
    if (!rootOk || !wOk) {
      const { proof } = buildQledgerFraudProof(env, parent, accFrom, entries)
      const claim = { inboxStart: b.inboxStart, inboxEnd: b.inboxEnd, dataHash: b.dataHash, prevStateRoot: b.prevStateRoot, stateRoot: b.stateRoot, withdrawalsRoot: b.withdrawalsRoot }
      if (checkQledgerFraud(env, claim, proof)) fraud = { batchIndex: b.batchIndex, status: b.status, proof, published: b.stateRoot, honest: bytesToHex(honest.stateRoot) }
    }
    for (const e of entries) {
      const p = e.poster === operator ? decodePost(e.payload) : undefined
      if (!p) { report.foreign++; continue }
      report.posts++
      const why = []
      const key = logKeys.get(p.logId)
      if (!key) why.push('log not in Chrome list')
      else if (!logSignatureValid(key, { timestamp: p.logTimestamp, treeSize: p.treeSize, rootHash: p.rootHash, logSignature: p.logSignature })) why.push('log signature')
      if (!verifyCosignature(witnessKey, { cosigner: witnessName, timestamp: p.witnessTimestamp, origin: p.origin, treeSize: p.treeSize, rootHash: p.rootHash, signature: p.signature })) why.push('witness signature')
      if (why.length) { report.bad.push({ batch: b.batchIndex, origin: p.origin, treeSize: p.treeSize, why }); continue }
      report.verified++
      const k = `${p.origin}|${p.treeSize}`, other = seen.get(k)
      if (other && !other.rootHash.equals(p.rootHash)) report.splitViews.push({ origin: p.origin, treeSize: p.treeSize, a: other, b: p })
      else seen.set(k, p)
    }
    if (fraud) ledger = parent // the chain rolls the inbox back; the resubmitted batch replays from the parent
    else report.batches++
    return fraud
  }

  return {
    report,
    // Audit every batch not yet seen, in order. Returns the fraud found in batches still open to challenge.
    async poll() {
      logKeys ??= new Map(usableLogs(await fetch(LOG_LIST, { headers: { 'user-agent': USER_AGENT } }).then(r => r.json())).map(l => [l.logId, l.key]))
      const found = []
      for (const b of (await rest.listBatches(rollupId, { startIndex: next })).sort((x, y) => x.batchIndex - y.batchIndex)) {
        if (b.batchIndex < next || b.status === 'rejected') continue
        if (b.status === 'challenged') break // wait for the chain to decide; later batches build on it
        const fraud = await auditBatch(b)
        if (!fraud) { next = b.batchIndex + 1; continue }
        const id = `${b.batchIndex}:${b.stateRoot}`
        if (!flagged.has(id)) { flagged.add(id); report.fraud.push({ ...fraud, proof: undefined }); found.push(fraud) }
        break
      }
      return found
    },
  }
}
