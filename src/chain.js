// QoreChain testnet (qorechain-diana) connections. Every native-lane transaction is hybrid-signed
// (secp256k1 + ML-DSA-87), so each client is connected with the account's post-quantum keypair.
import {
  createClient, deriveNativeAccount, deriveUnifiedAccount, derivePqcCanonical, directSignerFromPrivateKey, ensurePqcRegistered,
  EthNativeSigner, buildRegisterPqcKeyMsg,
} from '@qorechain/sdk'
import { StargateClient } from '@cosmjs/stargate'

export const NETWORK = 'testnet'
export const EVM_RPC = process.env.QORE_EVM_RPC || 'https://evm-testnet.qore.host'

// The cosmos-path account: holds the rollup stake and posts batches.
export async function connect(mnemonic) {
  const client = createClient({ network: NETWORK })
  const acct = await deriveNativeAccount(mnemonic)
  const pqcKeypair = derivePqcCanonical(acct.address, mnemonic)
  const signer = await directSignerFromPrivateKey(acct.privateKey, 'qor')
  const tx = await client.connectTx(signer, { pqcKeypair })
  return { client, tx, address: acct.address, pqcKeypair, rest: client.network.endpoints.rest }
}

export async function register(conn) {
  return ensurePqcRegistered(conn.tx, { pqcKeypair: conn.pqcKeypair, rest: conn.rest })
}

export async function balance(conn, address = conn.address) {
  const r = await fetch(`${conn.rest}/cosmos/bank/v1beta1/balances/${address}`).then(r => r.json())
  return Number(r.balances?.find(b => b.denom === 'uqor')?.amount ?? 0) / 1e6
}

// The unified account signs native-lane txs with its eth_secp256k1 key (keccak SignDoc), which cosmjs signers cannot
// produce, so it goes through EthNativeSigner over a plain StargateClient transport.
export async function connectEvm(mnemonic) {
  const client = createClient({ network: NETWORK })
  const { rest, rpc } = client.network.endpoints
  const acct = await deriveUnifiedAccount(mnemonic)
  const transport = await StargateClient.connect(rpc)
  const fee = { amount: [{ denom: 'uqor', amount: '400000' }], gas: '4000000' }
  const seq = async () => {
    const a = (await fetch(`${rest}/cosmos/auth/v1beta1/accounts/${acct.cosmos}`).then(r => r.json())).account
    const base = a.base_account ?? a
    return { accountNumber: BigInt(base.account_number), sequence: BigInt(base.sequence ?? 0) }
  }
  const send = async (messages, mode = 'hybrid') => {
    const signer = new EthNativeSigner(acct, { rest, signMode: mode })
    const r = await signer.signAndBroadcast(transport, { chainId: client.network.chainId, messages, fee, ...(await seq()) })
    if (r.code !== 0) throw new Error(`tx ${r.transactionHash} failed (${r.code}): ${r.rawLog}`)
    return r
  }
  return { client, acct, address: acct.cosmos, evm: acct.evm, rest, transport, send }
}

// One-time, classical-signed (the chain exempts this message from the hybrid rule).
export async function registerEvm(conn) {
  const st = await fetch(`${conn.rest}/qorechain/pqc/v1/account/${conn.address}`).then(r => r.json()).catch(() => ({}))
  if (st?.found) return { alreadyRegistered: true }
  const pub = Buffer.from(conn.acct.publicKey.replace(/^0x/, ''), 'hex')
  return conn.send([buildRegisterPqcKeyMsg(conn.address, { pqcKeypair: conn.acct.pqc, ecdsaPubkey: pub })], 'classical')
}
