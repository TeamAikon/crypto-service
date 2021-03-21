import { Asymmetric, ChainType, Context, PublicKey, Signature, VerifyPublcKeyParams } from '../../../models'
import { getChain } from '../../chains/chainConnection'
import { StateStore } from '../../../helpers/stateStore'
import { saveTransportKey } from '../transportKey'

/**
 *  Returns a single use public key along with a proof that this service has access to a private key that maps to a well-kwown public key
 *  Nonce is any random string
 *  Returns: an object that includes a public key and a signature (which is the nonce signed with the service's private key)
 */
export async function getTransportPublicKeyResolver(
  params: VerifyPublcKeyParams,
  context: Context,
  state: StateStore,
): Promise<{ transportPublicKey: PublicKey; signature: Signature }> {
  const { constants } = context
  const { nonce } = params
  const signature = await Asymmetric.sign(nonce, constants.BASE_PRIVATE_KEY)
  // Use generic 'nochain' functions to generateKeyPair
  const chain = await getChain(ChainType.NoChain, context)
  const keyPair = await chain.chainFunctions.generateKeyPair()
  const expiresOn = new Date(context.requestDateTime.getTime() + 1000 * constants.TRANSPORT_KEY_EXPIRE_IN_SECONDS)
  // store keyPair in memory (temporarily)
  // state.transportKeyStore.push({ publicKey: keyPair.publicKey, privateKey: keyPair.privateKey, expiresOn })
  const transportKey = { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey, expiresOn }
  await saveTransportKey(transportKey, context)
  return {
    transportPublicKey: keyPair.publicKey,
    signature,
  }
}
