import { Logger } from 'aikon-js'

export interface Lookup {
  [key: string]: any
}

export type AppId = string

export type Context = {
  /** appId of authenticated user or agent */
  appId?: AppId
  processId: string
  logger: Logger
}

export type Hash = string
export type PublicKey = string
export type SaltName = string
export type SymmetricEncryptedItem = string
export type AsymmetricEncryptedItem = string
export type SymmetricPassword = string

/** Flavor of chain network */
export enum ChainPlatformType {
  Algorand = 'algorand',
  Eos = 'eos',
  Ethereum = 'ethereum',
}

/** Supported chain types */
export enum ChainType {
  AlgorandV1 = 'algorand',
  EosV2 = 'eos',
  EthereumV1 = 'ethereum',
}

/** Athorization token sent (encrypted) by caller
 *  Ensures that the request is coming from an authorized called 
 *  and the request is only executed/authorized once 
 *  Optionally includes symmetric password for encryption/decryption */
export type AuthToken = {
  paramsHash: Hash
  password?: SymmetricPassword,
  validFrom: Date
  expiresOn: Date
}

/** Options for asym encryption */
export type AsymmetricOptions = {
  /** array of public keys - in order to be used for asym encryption wrapping */
  publicKeys: PublicKey[]
  /** optional initialization vector */
  iv?: string
  /** any data or secret to be included in ecnrypted payload */
  s1?: string
  /** any data or secret to be included in ecnrypted payload */
  s2?: string
}

/** Options for ECC sym encryption (along with password) */
export type SymmetricEccOptions = {
  /** nubmer of iterations */
  iter?: number
  /** name of salt secret - must match a saltName registered on the server */
  saltName?: string
  /** salt value - if provided, this is used instead of saltName */
  salt?: string
}

/** Options for ED25519 sym encryption using (along with password) */
export type SymmetricEd25519Options = {
  /** nubmer of iterations */
  N?: number
  /** name of salt secret - must match a saltName registered on the server */
  saltName?: string
  /** salt value - if provided, this is used instead of saltName */
  salt?: string
}
