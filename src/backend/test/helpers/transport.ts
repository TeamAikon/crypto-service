import { Crypto } from '@open-rights-exchange/chainjs'
import { Asymmetric } from '@open-rights-exchange/chainjs/dist/crypto'
import { Base64 } from 'js-base64'
import fetch from 'node-fetch'

declare let global: any

const headers: any = {
  'api-key': global.TEST_APP_API_KEY,
  'Content-Type': 'application/json',
  Accept: 'application/json',
}

export async function encryptWithTransportKey(value: string, transportPublicKey: string) {
  // hash the body of the request
  // encrypt with public key of service
  const encrypted = Crypto.Asymmetric.encryptWithPublicKey(transportPublicKey, value)
  return Base64.encode(JSON.stringify(encrypted))
}

export async function getTransportKey() {
  console.log('--------------- getTransportKey -------------->')
  const url = `${global.TEST_SERVER_PATH}/get-transport-key`
  const nonce = 'unique-string' // Should use GUID here instead of a fixed string
  const response = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({ nonce }),
  })

  const data = await response.json()
  const { signature, transportPublicKey } = data || {}
  const signedWithWellKnownPublicKey = Asymmetric.verifySignedWithPublicKey(nonce, global.BASE_PUBLIC_KEY, signature)
  if (!signedWithWellKnownPublicKey) {
    throw new Error(
      `Service could not verify control of well-known public key. Are you using the right endpoint? Well-known PublicKey expected: ${global.BASE_PUBLIC_KEY}`,
    )
  }
  return transportPublicKey
}
