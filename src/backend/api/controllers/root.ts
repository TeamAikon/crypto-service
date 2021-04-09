import { NextFunction, Request, Response } from 'express'
import { globalLogger } from '../../../helpers/logger'
import { addAppIdAndChainTypeToContextFromApiKey, createContext } from '../context'
import {
  assertBodyHasAtLeastOneOfValues,
  assertBodyHasOnlyOneOfValues,
  assertBodyhasRequiredValues,
  assertBodyValueIsArrayIfExists,
  assertHeaderhasRequiredValues,
  extractEncryptedPayload,
  returnResponse,
  unwrapTransportEncryptedPasswordInSymOptions,
} from '../helpers'
import { Config, Context, ErrorSeverity, ErrorType, HttpStatusCode } from '../../../models'
import {
  decryptWithPasswordResolver,
  decryptWithPrivateKeysResolver,
  encryptResolver,
  generateKeysResolver,
  getTransportPublicKeyResolver,
  recoverAndReencryptResolver,
  signResolver,
  verifyPublicKeyResolver,
} from '../../resolvers/crypto'
import { logError, ServiceError } from '../../../helpers/errors'
import { StateStore } from '../../../helpers/stateStore'

// Root-level routes
async function v1Root(req: Request, res: Response, next: NextFunction, config: Config, state: StateStore) {
  const now = new Date()
  const { action } = req.params
  const context = createContext(req, config, now)
  try {
    await addAppIdAndChainTypeToContextFromApiKey(req, context)
  } catch (error) {
    return returnResponse(req, res, HttpStatusCode.BAD_REQUEST_400, null, null, error)
  }
  switch (action) {
    case 'decrypt-with-password':
      return handleDecryptWithPassword(req, res, next, context, state)
    case 'decrypt-with-private-keys':
      return handleDecryptWithPrivateKeys(req, res, next, context, state)
    case 'encrypt':
      return handleEncrypt(req, res, next, context, state)
    case 'generate-keys':
      return handleGenerateKeys(req, res, next, context, state)
    case 'get-transport-key':
      return handleGetTransportKey(req, res, next, context, state)
    case 'verify-public-key':
      return handleVerifyPublicKey(req, res, next, context, state)
    case 'recover-and-reencrypt':
      return handleRecoverAndReencrypt(req, res, next, context, state)
    case 'sign':
      return handleSign(req, res, next, context, state)
    default:
      return returnResponse(req, res, HttpStatusCode.NOT_FOUND_404, { errorMessage: 'Not a valid endpoint' }, context)
  }
}
// api/decrypt-with-password
/** Calls resolver to decrypt the payload using provided password and options */
export async function handleDecryptWithPassword(
  req: Request,
  res: Response,
  next: NextFunction,
  context: Context,
  state: StateStore,
) {
  const funcName = 'api/decrypt-with-password'
  try {
    globalLogger.trace('called handleDecryptWithPassword')
    assertHeaderhasRequiredValues(req, ['api-key'], funcName)
    assertBodyhasRequiredValues(req, ['chainType', 'encrypted', 'symmetricOptions'], funcName)
    assertBodyValueIsArrayIfExists(req, ['returnAsymmetricOptions'], funcName)
    const { chainType, encrypted, returnAsymmetricOptions, symmetricOptions } = req.body

    if (symmetricOptions) {
      await unwrapTransportEncryptedPasswordInSymOptions(symmetricOptions, context)
    }

    const response = await decryptWithPasswordResolver(
      { chainType, encrypted, symmetricOptions, returnAsymmetricOptions },
      context,
    )

    return await returnResponse(req, res, HttpStatusCode.OK_200, response, context)
  } catch (error) {
    logError(context, error, ErrorSeverity.Info, funcName)
    return returnResponse(req, res, HttpStatusCode.BAD_REQUEST_400, null, context, error)
  }
}

// api/decrypt-with-private-keys
/** Calls resolver to decrypt the payload using provided password and options */
export async function handleDecryptWithPrivateKeys(
  req: Request,
  res: Response,
  next: NextFunction,
  context: Context,
  state: StateStore,
) {
  const funcName = 'api/decrypt-with-private-keys'

  try {
    globalLogger.trace('called handleDecryptWithPrivateKeys')
    assertHeaderhasRequiredValues(req, ['api-key'], funcName)
    assertBodyhasRequiredValues(req, ['chainType'], funcName)
    assertBodyHasOnlyOneOfValues(req, ['encrypted', 'encryptedTransportEncrypted'], funcName)
    assertBodyHasOnlyOneOfValues(req, ['asymmetricEncryptedPrivateKeys', 'symmetricEncryptedPrivateKeys'], funcName)
    assertBodyValueIsArrayIfExists(req, ['returnAsymmetricOptions'], funcName)
    const {
      chainType,
      encryptedTransportEncrypted,
      asymmetricTransportEncryptedPrivateKeys,
      symmetricEncryptedPrivateKeys,
      symmetricOptionsForEncryptedPrivateKeys,
      returnAsymmetricOptions,
    } = req.body
    let { asymmetricEncryptedPrivateKeys } = req.body
    let { encrypted } = req.body

    // if (symmetricEncryptedPrivateKeys) {
    //   await unwrapTransportEncryptedPasswordInSymOptions(symmetricEncryptedPrivateKeys, context)
    // }

    if (symmetricOptionsForEncryptedPrivateKeys) {
      await unwrapTransportEncryptedPasswordInSymOptions(symmetricOptionsForEncryptedPrivateKeys, context)
    }

    // extract asymmetricEncryptedPrivateKeys using transportPublicKey
    if (asymmetricTransportEncryptedPrivateKeys) {
      const encryptedKeys = await extractEncryptedPayload(
        asymmetricTransportEncryptedPrivateKeys,
        'asymmetricTransportEncryptedPrivateKeys',
        context,
        state,
      )
      asymmetricEncryptedPrivateKeys = encryptedKeys
    }

    // extract encrypted using transportPublicKey
    if (encryptedTransportEncrypted) {
      encrypted = await extractEncryptedPayload(
        encryptedTransportEncrypted,
        'encryptedTransportEncrypted',
        context,
        state,
      )
    }

    const response = await decryptWithPrivateKeysResolver(
      {
        chainType,
        encrypted,
        asymmetricEncryptedPrivateKeys,
        symmetricEncryptedPrivateKeys,
        symmetricOptionsForEncryptedPrivateKeys,
        returnAsymmetricOptions,
      },
      context,
    )

    return await returnResponse(req, res, HttpStatusCode.OK_200, response, context)
  } catch (error) {
    logError(context, error, ErrorSeverity.Info, funcName)
    return returnResponse(req, res, HttpStatusCode.BAD_REQUEST_400, null, context, error)
  }
}

// api/recover-and-reencrypt
/** Calls resolver to decrypt the payload using provided password and options */
export async function handleRecoverAndReencrypt(
  req: Request,
  res: Response,
  next: NextFunction,
  context: Context,
  state: StateStore,
) {
  const funcName = 'api/recover-and-reencrypt'
  let encryptedPayload
  let password
  try {
    globalLogger.trace('called handleRecoverAndReencrypt')
    assertHeaderhasRequiredValues(req, ['api-key'], funcName)
    assertBodyhasRequiredValues(req, ['chainType'], funcName)
    assertBodyHasOnlyOneOfValues(req, ['encrypted', 'encryptedTransportEncrypted'], funcName)
    assertBodyHasAtLeastOneOfValues(
      req,
      ['asymmetricTransportEncryptedPrivateKeys', 'asymmetricEncryptedPrivateKeys'],
      funcName,
    )
    assertBodyHasOnlyOneOfValues(
      req,
      ['asymmetricTransportEncryptedPrivateKeys', 'asymmetricEncryptedPrivateKeys'],
      funcName,
    )
    assertBodyHasAtLeastOneOfValues(req, ['symmetricOptionsForReencrypt', 'asymmetricOptionsForReencrypt'], funcName)
    assertBodyValueIsArrayIfExists(req, ['asymmetricOptionsForReencrypt'], funcName)

    const {
      chainType,
      encrypted,
      encryptedTransportEncrypted,
      asymmetricTransportEncryptedPrivateKeys,
      symmetricOptionsForReencrypt,
      asymmetricOptionsForReencrypt,
    } = req.body

    let { asymmetricEncryptedPrivateKeys } = req.body

    // extract encrypted payload from encryptedTransportEncrypted (if provided)
    if (encryptedTransportEncrypted) {
      encryptedPayload = await extractEncryptedPayload(
        encryptedTransportEncrypted,
        'encryptedTransportEncrypted',
        context,
        state,
      )
    } else {
      encryptedPayload = encrypted
    }

    // extract password (if provided in sym options)
    if (symmetricOptionsForReencrypt) {
      password = await unwrapTransportEncryptedPasswordInSymOptions(symmetricOptionsForReencrypt, context)
    }

    if (!asymmetricEncryptedPrivateKeys) {
      // extract asymmetricEncryptedPrivateKeys
      asymmetricEncryptedPrivateKeys = await extractEncryptedPayload(
        asymmetricTransportEncryptedPrivateKeys,
        'asymmetricTransportEncryptedPrivateKeys',
        context,
        state,
      )
    }

    const response = await recoverAndReencryptResolver(
      {
        chainType,
        encrypted: encryptedPayload,
        asymmetricEncryptedPrivateKeys,
        symmetricOptionsForReencrypt,
        asymmetricOptionsForReencrypt,
      },
      context,
    )

    return await returnResponse(req, res, HttpStatusCode.OK_200, response, context)
  } catch (error) {
    logError(context, error, ErrorSeverity.Info, funcName)
    return returnResponse(req, res, HttpStatusCode.BAD_REQUEST_400, null, context, error)
  }
}

// api/encrypt
/** Calls resolver to encrypt the payload using one or more public/private key pairs for a specific blockchain */
export async function handleEncrypt(
  req: Request,
  res: Response,
  next: NextFunction,
  context: Context,
  state: StateStore,
) {
  const funcName = 'api/encrypt'
  try {
    globalLogger.trace('called handleEncrypt')
    assertHeaderhasRequiredValues(req, ['api-key'], funcName)
    assertBodyhasRequiredValues(req, ['chainType', 'toEncrypt'], funcName)
    assertBodyHasAtLeastOneOfValues(req, ['asymmetricOptions', 'symmetricOptions'], funcName)
    assertBodyValueIsArrayIfExists(req, ['asymmetricOptions'], funcName)
    const { asymmetricOptions, chainType, toEncrypt, symmetricOptions } = req.body

    if (symmetricOptions) {
      await unwrapTransportEncryptedPasswordInSymOptions(symmetricOptions, context)
    }

    const response = await encryptResolver({ chainType, asymmetricOptions, symmetricOptions, toEncrypt }, context)

    return await returnResponse(req, res, HttpStatusCode.OK_200, response, context)
  } catch (error) {
    logError(context, error, ErrorSeverity.Info, funcName)
    return returnResponse(req, res, HttpStatusCode.BAD_REQUEST_400, null, context, error)
  }
}

// api/generate-keys
/** Calls resolver to generate one or more public/private key pairs for a specific blockchain */
export async function handleGenerateKeys(
  req: Request,
  res: Response,
  next: NextFunction,
  context: Context,
  state: StateStore,
) {
  const funcName = 'api/generate-keys'
  try {
    globalLogger.trace('called handleGenerateKeys')
    assertHeaderhasRequiredValues(req, ['api-key'], funcName)
    assertBodyhasRequiredValues(req, ['chainType'], funcName)
    assertBodyHasAtLeastOneOfValues(req, ['asymmetricOptions', 'symmetricOptions'], funcName)
    assertBodyValueIsArrayIfExists(req, ['asymmetricOptions'], funcName)
    const { asymmetricOptions, chainType, keyCount, symmetricOptions } = req.body

    if (symmetricOptions) {
      await unwrapTransportEncryptedPasswordInSymOptions(symmetricOptions, context)
    }

    const response = await generateKeysResolver({ chainType, keyCount, asymmetricOptions, symmetricOptions }, context)

    return await returnResponse(req, res, HttpStatusCode.OK_200, response, context)
  } catch (error) {
    logError(context, error, ErrorSeverity.Info, funcName)
    return returnResponse(req, res, HttpStatusCode.BAD_REQUEST_400, null, context, error)
  }
}

// api/sign
/** Calls resolver to sign a transaction with one or more private key pairs for a specific blockchain */
export async function handleSign(req: Request, res: Response, next: NextFunction, context: Context, state: StateStore) {
  const funcName = 'api/sign'
  try {
    globalLogger.trace('called handleSign')
    assertHeaderhasRequiredValues(req, ['api-key'], funcName)
    assertBodyhasRequiredValues(req, ['chainType', 'toSign'], funcName)
    assertBodyHasAtLeastOneOfValues(
      req,
      ['asymmetricTransportEncryptedPrivateKeys', 'symmetricEncryptedPrivateKeys', 'asymmetricEncryptedPrivateKeys'],
      funcName,
    )
    assertBodyHasOnlyOneOfValues(
      req,
      ['asymmetricTransportEncryptedPrivateKeys', 'asymmetricEncryptedPrivateKeys'],
      funcName,
    )
    assertBodyValueIsArrayIfExists(req, ['symmetricEncryptedPrivateKeys'], funcName)
    const {
      chainType,
      toSign,
      symmetricOptions,
      asymmetricTransportEncryptedPrivateKeys,
      symmetricEncryptedPrivateKeys,
    } = req.body

    let { asymmetricEncryptedPrivateKeys } = req.body

    if (symmetricOptions) {
      await unwrapTransportEncryptedPasswordInSymOptions(symmetricOptions, context)
    }

    if (!asymmetricEncryptedPrivateKeys) {
      // extract asymmetricEncryptedPrivateKeys
      asymmetricEncryptedPrivateKeys = await extractEncryptedPayload(
        asymmetricTransportEncryptedPrivateKeys,
        'asymmetricTransportEncryptedPrivateKeys',
        context,
        state,
      )
    }

    if (asymmetricEncryptedPrivateKeys && !Array.isArray(asymmetricEncryptedPrivateKeys)) {
      const param = asymmetricTransportEncryptedPrivateKeys
        ? '(within asymmetricTransportEncryptedPrivateKeys)'
        : 'asymmetricEncryptedPrivateKeys'
      const msg = `Bad parameter(s) in request body. 'encrypted' param ${param} must be an array. If only one value, enclose it in an array i.e. [ ].`
      throw new ServiceError(msg, ErrorType.BadParam, funcName)
    }

    const response = await signResolver(
      {
        chainType,
        toSign,
        symmetricOptions,
        asymmetricEncryptedPrivateKeys,
        symmetricEncryptedPrivateKeys,
      },
      context,
    )

    return await returnResponse(req, res, HttpStatusCode.OK_200, response, context)
  } catch (error) {
    logError(context, error, ErrorSeverity.Info, funcName)
    return returnResponse(req, res, HttpStatusCode.BAD_REQUEST_400, null, context, error)
  }
}

// api/get-transport-key
/** Returns a single use public key for caller to use to (asymmetrically) encrypt all data sent to this server */
export async function handleGetTransportKey(
  req: Request,
  res: Response,
  next: NextFunction,
  context: Context,
  state: StateStore,
) {
  const funcName = 'api/get-transport-key'
  try {
    globalLogger.trace('called handleGetTransportKey')
    assertBodyhasRequiredValues(req, ['nonce'], funcName)
    assertHeaderhasRequiredValues(req, ['api-key'], funcName)
    const { appId, maxUseCount, nonce } = req.body
    const response = await getTransportPublicKeyResolver({ appId, maxUseCount, nonce }, context, state)
    return await returnResponse(req, res, HttpStatusCode.OK_200, response, context)
  } catch (error) {
    logError(context, error, ErrorSeverity.Info, funcName)
    return returnResponse(req, res, HttpStatusCode.BAD_REQUEST_400, null, context, error)
  }
}

// api/public-key
/** Returns the public key for which all incoming secrets should be asymmetrically encrypted */
export async function handleVerifyPublicKey(
  req: Request,
  res: Response,
  next: NextFunction,
  context: Context,
  state: StateStore,
) {
  const funcName = 'api/verify-public-key'
  try {
    globalLogger.trace('called handlePublicKey')
    assertBodyhasRequiredValues(req, ['nonce'], funcName)
    assertHeaderhasRequiredValues(req, ['api-key'], funcName)
    const { nonce } = req.body
    const response = await verifyPublicKeyResolver({ nonce }, context)
    return await returnResponse(req, res, HttpStatusCode.OK_200, response, context)
  } catch (error) {
    logError(context, error, ErrorSeverity.Info, funcName)
    return returnResponse(req, res, HttpStatusCode.BAD_REQUEST_400, null, context, error)
  }
}

export { v1Root }
