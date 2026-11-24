# Tree Rings design (day 1, 24 November 2026)

## What is checked where

| Claim | Who enforces it |
|---|---|
| A cosigned tree head really is the log's (its own ECDSA/Ed25519 signature) | the witness, before cosigning; anyone can re-check from the batch data |
| A new head extends the previous one (RFC 6962 consistency proof) | the witness, before cosigning; the EVM bond contract when slashing |
| A batch's state root is the canonical commitment of its data | QoreChain itself (optimistic fraud challenge on the rollup) |
| A witness never signs two heads of one log that are not append-only | the EVM bond contract: two ML-DSA-87 cosignatures from the same witness + a failing consistency check = slash |

## Facts read from the live testnet (qorechain-diana, 24 Nov)

- Optimistic rollups post their batch data: `sealed-scouts-1` batch 1520 and `vigil-1` batch 31 both carry a non-empty `data_hash`, an inbox range and `proof_type: fraud`, and finalize after the challenge window.
- `GET /qorechain/rdk/v1/params`: stake 10,000 QOR (1 % burned at creation), `min_submitter_bond` 1,000 QOR, `default_challenge_window` 3,600 s, `max_posted_data_bytes` 131,072 per batch.
- 13 rollups are registered; the multilayer module allows 64 sidechains.

## Consequence

The rollup's own fraud challenge cannot decide whether a log is honest: it checks that the state root matches the posted data. The witness-accountability claim therefore rests on a separate EVM contract that holds witness bonds and slashes on provable equivocation, verified with the chain's ML-DSA-87 precompile and an on-chain consistency-proof check. The rollup challenge stays in the demo as the "wrong state root" case.

## Order of work

1. CT core offline, with tests against real logs: log list, `get-sth` and tiled checkpoints, log-signature checks, consistency proofs, signed-note cosignatures.
2. Bond contract (Foundry) with the slashing path, tested.
3. Register the operator's post-quantum key, then create the `tree-rings` rollup once, optimistic profile.
4. Batches with data posting and anchors, settlement-receipt verification, a withdrawal, the watchtower from a second account.
5. Sealed watchlists (QoreSeal), threat model, site, video.
