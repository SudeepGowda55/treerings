// Sealed watchlists. A domain owner seals the names they care about to the witness's ML-KEM-1024 key (QoreSeal,
// mlkem mode: only the key on chain is needed) and posts the envelope to the rollup inbox. The witness opens it,
// checks certificates it reads from the logs against it, and seals each hit back to the owner. On chain, anyone
// sees only that an account posted an envelope of some size; the names and the hits stay private.
// The envelope's AAD is the poster's address: a copy re-posted by anyone else will not open, so nobody can
// learn the hits for someone else's list.
import { seal, open, deriveSealKeys } from '@qorechain/qoreseal'
import { fetchMlkemPublicKey } from '@qorechain/qoreseal/network'

const LIST = Buffer.from('TRW1'), ALERT = Buffer.from('TRA1')
const P_LIST = 'treerings-watchlist/v1', P_ALERT = 'treerings-alert/v1'
const enc = o => new TextEncoder().encode(JSON.stringify(o))
const dec = b => JSON.parse(new TextDecoder().decode(b))
const mlkem = mlkemPublicKey => ({ mlkemPublicKey })

export const sealKeys = mnemonic => deriveSealKeys({ mnemonic })

export async function sealWatchlist({ rest, chainId, owner, witness, domains }) {
  const recipients = [mlkem(await fetchMlkemPublicKey({ rest, address: witness }))]
  return Buffer.concat([LIST, seal({ chainId, purpose: P_LIST, recipients, mode: 'mlkem', aad: Buffer.from(owner), plaintext: enc({ domains }) })])
}

// undefined unless `data` is a list sealed to these keys by `poster`
export function openWatchlist({ chainId, keys, poster, data }) {
  if (!Buffer.from(data.subarray(0, 4)).equals(LIST)) return undefined
  try { return { owner: poster, ...dec(open({ chainId, purpose: P_LIST, envelope: data.subarray(4), keys, aad: Buffer.from(poster) })) } } catch { return undefined }
}

export async function sealAlert({ rest, chainId, owner, hits }) {
  const recipients = [mlkem(await fetchMlkemPublicKey({ rest, address: owner }))]
  return Buffer.concat([ALERT, seal({ chainId, purpose: P_ALERT, recipients, mode: 'mlkem', aad: Buffer.from(owner), plaintext: enc({ hits }) })])
}

export function openAlert({ chainId, keys, owner, data }) {
  if (!Buffer.from(data.subarray(0, 4)).equals(ALERT)) return undefined
  try { return dec(open({ chainId, purpose: P_ALERT, envelope: data.subarray(4), keys, aad: Buffer.from(owner) })) } catch { return undefined }
}

// "example.com" covers example.com and every name under it; a wildcard cert "*.example.com" matches too.
export function matches(name, domain) {
  name = name.replace(/^\*\./, '').toLowerCase(); domain = domain.toLowerCase().replace(/^\.+/, '')
  return name === domain || name.endsWith('.' + domain)
}
