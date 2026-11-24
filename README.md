# Tree Rings

**A post-quantum witness for the web's Certificate Transparency logs, settled as a rollup on QoreChain.**

Every TLS certificate a browser trusts is recorded in Certificate Transparency (CT) logs. Each log publishes signed tree heads that commit to its whole history, and those signatures are classical (ECDSA). After Q-Day, someone with a quantum computer could forge a log's signature and show a rewritten history, or a split view to a single victim, and nobody could tell.

Tree Rings watches the logs Chrome trusts, live. For every new tree head it checks the log's own signature and the consistency proof that the new tree extends the old one, then cosigns the head with ML-DSA-87. Cosigned heads are batched and settled on QoreChain, and a watchtower anyone can run checks every batch against the public logs.

Built for [Build Before Q-Day](https://build.qorechain.io/p/tree-rings) (Protocol Builders) by team Matcrypt (Sudeep and Manvith).

## Status

Day 1 (24 November 2026). Checked so far, live:

- Chrome's CT log list holds 50 usable logs (RFC 6962 and static-ct tiled logs); their tree heads and checkpoints answer publicly, and Cloudflare's Nimbus2026 log alone holds 6.8 billion entries.
- The QoreChain testnet (qorechain-diana) runs optimistic rollups today (13 registered), and the RDK module parameters were read from the live chain.

## Prior work we build on

Post-quantum witness cosigning is not new: [TrustFabric's witnesses already support ML-DSA](https://blog.transparency.dev/trustfabric-and-post-quantum), and [Merkle Tree Certificates](https://developers.google.com/public-key-infrastructure/faq/what-are-mtcs) move the web towards post-quantum, cosigned logs. Tree Rings' part is accountability: witnesses whose cosignatures are settled on a public chain, with bonds that a provably wrong cosignature loses.

## Licence

MIT
