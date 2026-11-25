// Live check: QoreChain's pqcVerify precompile (0x...0a01, qorechain-diana) accepts a Tree Rings ML-DSA-87
// cosignature and refuses a tampered message. Read-only eth_call: no account, no fee.
import { createPublicClient, http, parseAbi } from 'viem'
import { createHash } from 'node:crypto'
import { witnessFromSeed, cosign, cosignedSubtreeBytes } from '../src/cosign.js'

const client = createPublicClient({ transport: http(process.env.QORE_EVM_RPC || 'https://evm-testnet.qore.host') })
const abi = parseAbi(['function pqcVerify(bytes pubkey, bytes signature, bytes message) view returns (bool)'])
const w = witnessFromSeed('treerings.witness/probe', Buffer.alloc(32, 1))
const c = cosign(w, { url: 'https://ct.cloudflare.com/logs/nimbus2026/', treeSize: 6828176246, rootHash: createHash('sha256').update('x').digest() }, 1795600000)
const msg = cosignedSubtreeBytes({ cosigner: c.cosigner, timestamp: c.timestamp, origin: c.origin, end: c.treeSize, hash: c.rootHash })
const hex = b => '0x' + Buffer.from(b).toString('hex')
const verify = m => client.readContract({ address: '0x0000000000000000000000000000000000000a01', abi, functionName: 'pqcVerify', args: [hex(w.publicKey), hex(c.signature), hex(m)] })
const bad = Buffer.from(msg); bad[bad.length - 1] ^= 1
const honest = await verify(msg), tampered = await verify(bad)
console.log({ chainId: await client.getChainId(), honest, tampered })
if (!honest || tampered) process.exit(1)
