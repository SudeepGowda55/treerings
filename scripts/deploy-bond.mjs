// Deploys WitnessBond on qorechain-diana from the operator's unified (EVM) identity and bonds the operator's witness.
// Needs QORE_MNEMONIC and WITNESS_SEED (hex, 32 bytes) in the environment. Writes deployments/testnet.json.
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { openEvmWindowMsg, fetchEvmWindow } from '@qorechain/sdk'
import { createPublicClient, createWalletClient, http, defineChain, parseEther, getContract } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { connectEvm, EVM_RPC } from '../src/chain.js'
import { witnessFromSeed } from '../src/cosign.js'

const NAME = 'treerings.witness/1'
const OUT = new URL('../deployments/testnet.json', import.meta.url)
const art = JSON.parse(readFileSync(new URL('../contracts/out/WitnessBond.sol/WitnessBond.json', import.meta.url)))
const chain = defineChain({ id: 9800, name: 'qorechain-diana', nativeCurrency: { name: 'QOR', symbol: 'QOR', decimals: 18 }, rpcUrls: { default: { http: [EVM_RPC] } } })

const ev = await connectEvm(process.env.QORE_MNEMONIC)
const account = privateKeyToAccount(ev.acct.privateKey)
const pub = createPublicClient({ chain, transport: http() })
const wallet = createWalletClient({ chain, transport: http(), account })

const w = await fetchEvmWindow({ rest: ev.rest, address: ev.address })
if (!w.live || w.remainingTxs < 3n) {
  // value budget in uqor: the 25 QOR bond plus fees for a handful of transactions
  const r = await ev.send([openEvmWindowMsg({ sender: ev.address, blocks: 17280, maxTxs: 20, maxValue: '40000000' })])
  console.log('window opened', r.transactionHash)
}

const deployed = existsSync(OUT) ? JSON.parse(readFileSync(OUT)) : {}
if (!deployed.witnessBond) {
  const hash = await wallet.deployContract({ abi: art.abi, bytecode: art.bytecode.object, args: [parseEther('10'), 600n] })
  const rc = await pub.waitForTransactionReceipt({ hash })
  Object.assign(deployed, { chainId: 9800, witnessBond: rc.contractAddress, deployTx: hash, deployer: account.address, minBond: '10 QOR', unbondDelaySeconds: 600 })
  writeFileSync(OUT, JSON.stringify(deployed, null, 2) + '\n')
  console.log('WitnessBond', rc.contractAddress, hash)
}

const bond = getContract({ address: deployed.witnessBond, abi: art.abi, client: { public: pub, wallet } })
const witness = witnessFromSeed(NAME, Buffer.from(process.env.WITNESS_SEED, 'hex'))
const [owner] = await bond.read.witness([NAME])
if (owner === '0x0000000000000000000000000000000000000000') {
  const hash = await bond.write.register([NAME, `0x${witness.publicKey.toString('hex')}`], { value: parseEther('25') })
  await pub.waitForTransactionReceipt({ hash })
  Object.assign(deployed, { witness: NAME, witnessKeyId: witness.keyId.toString('hex'), registerTx: hash, bond: '25 QOR' })
  writeFileSync(OUT, JSON.stringify(deployed, null, 2) + '\n')
  console.log('witness registered', hash)
}
console.log(deployed)
process.exit(0)
