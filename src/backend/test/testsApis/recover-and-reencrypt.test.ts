/* eslint-disable consistent-return */
/* eslint-disable jest/no-done-callback */
import supertest from 'supertest'
import { Server } from 'http'
import { ChainFactory, ChainType, Crypto } from '@open-rights-exchange/chainjs'
import {
  openDB,
  closeDB,
  clearDB,
  initializeDB,
  createExpressServerForTest,
  encryptWithTransportKey,
  getTransportKey,
} from '../helpers'
import { setupGlobalConstants } from '../config/constants'

declare let global: any

const headers: any = {
  'api-key': global.TEST_APP_API_KEY,
  'Content-Type': 'application/json',
  Accept: 'application/json',
}
const apiUrl = `${global.TEST_SERVER_PATH}/recover-and-reencrypt`
/**
 * Test API Endpoints
 */

// Using supertest - https://github.com/visionmedia/supertest
// Example: - https://losikov.medium.com/part-4-node-js-express-typescript-unit-tests-with-jest-5204414bf6f0

let server: Server
const now = new Date()

beforeAll(async () => {
  await openDB('test_cryptoapi')
  await initializeDB()
  server = await createExpressServerForTest()
  setupGlobalConstants()
})

afterAll(async () => {
  server.close()
  await clearDB()
  await closeDB()
})

describe('Test api /recover-and-reencrypt endpoint', () => {
  jest.setTimeout(10000)

  it('should return 200 & return encrypted private key', async done => {
    const chain = new ChainFactory().create(ChainType.AlgorandV1, [{ url: null }])
    const prviateKeyToEncrypt = 'private-key-to-recover'
    const recoverAndReencryptParams: any = {
      chainType: 'algorand',
      asymmetricOptionsForReencrypt: [
        {
          publicKeys: [global.ALGO_PUB_KEY],
        },
      ],
      symmetricOptionsForReencrypt: { ...global.SYMMETRIC_ED25519_OPTIONS },
    }
    const transportPublicKey = await getTransportKey()
    // encrypt a payload using our public key - in this example, its a private key we've 'backed-up'
    const privateKeyToRecover = await chain.encryptWithPublicKey(prviateKeyToEncrypt, global.ALGO_PUB_KEY)
    // wrap the encrypted payload with the transport public key
    recoverAndReencryptParams.encryptedTransportEncrypted = await encryptWithTransportKey(
      privateKeyToRecover,
      transportPublicKey,
    )
    // encrypt the private keys we'll use to decrypt the privateKeyToRecover
    const encryptedPrivateKey = JSON.stringify(
      Crypto.Asymmetric.encryptWithPublicKey(global.BASE_PUBLIC_KEY, global.ALGO_PRIVATE_KEY),
    )

    // wrap the encrypted keys with the transport public key
    recoverAndReencryptParams.asymmetricTransportEncryptedPrivateKeys = await encryptWithTransportKey(
      encryptedPrivateKey,
      transportPublicKey,
    )
    // wrap password with the transport public key
    recoverAndReencryptParams.symmetricOptionsForReencrypt.transportEncryptedPassword = await encryptWithTransportKey(
      global.MY_PASSWORD,
      transportPublicKey,
    )

    supertest(server)
      .post('/recover-and-reencrypt')
      .set(headers)
      .send({ ...recoverAndReencryptParams })
      .expect('Content-Type', /json/)
      .expect(200)
      .end(async (err, res) => {
        if (err) return done(err)
        const encryptedString = chain.toAsymEncryptedDataString(
          JSON.stringify(JSON.parse(res.body.asymmetricEncryptedStrings[0])[0]),
        )
        const decryptedString = await chain.decryptWithPrivateKey(encryptedString, global.ALGO_PRIVATE_KEY)
        expect(decryptedString).toMatch(prviateKeyToEncrypt)
        done()
      })
  })

  it('should return 200 & return encrypted private key symmetric only', async done => {
    const chain = new ChainFactory().create(ChainType.AlgorandV1, [{ url: null }])
    const prviateKeyToEncrypt = 'private-key-to-recover'
    const recoverAndReencryptParams: any = {
      chainType: 'algorand',
      symmetricOptionsForReencrypt: { ...global.SYMMETRIC_ED25519_OPTIONS },
    }
    const transportPublicKey = await getTransportKey()

    // encrypt a payload using our public key - in this example, its a private key we've 'backed-up'
    const privateKeyToRecover = await chain.encryptWithPublicKey(prviateKeyToEncrypt, global.ALGO_PUB_KEY)
    // wrap the encrypted payload with the transport public key
    recoverAndReencryptParams.encryptedTransportEncrypted = await encryptWithTransportKey(
      privateKeyToRecover,
      transportPublicKey,
    )
    // encrypt the private keys we'll use to decrypt the privateKeyToRecover
    const encryptedPrivateKey = JSON.stringify(
      Crypto.Asymmetric.encryptWithPublicKey(global.BASE_PUBLIC_KEY, global.ALGO_PRIVATE_KEY),
    )

    // wrap the encrypted keys with the transport public key
    recoverAndReencryptParams.asymmetricTransportEncryptedPrivateKeys = await encryptWithTransportKey(
      encryptedPrivateKey,
      transportPublicKey,
    )
    // wrap password with the transport public key
    recoverAndReencryptParams.symmetricOptionsForReencrypt.transportEncryptedPassword = await encryptWithTransportKey(
      global.MY_PASSWORD,
      transportPublicKey,
    )

    supertest(server)
      .post('/recover-and-reencrypt')
      .set(headers)
      .send({ ...recoverAndReencryptParams })
      .expect('Content-Type', /json/)
      .expect(200)
      .end(async (err, res) => {
        if (err) return done(err)
        const decryptedString = chain.decryptWithPassword(
          res.body.symmetricEncryptedString,
          global.MY_PASSWORD,
          global.SYMMETRIC_ED25519_OPTIONS,
        )
        expect(decryptedString).toMatch(prviateKeyToEncrypt)
        done()
      })
  })

  it('should return 200 & return encrypted private -> assymetricEncryptedPrivateKeys only', async done => {
    const chain = new ChainFactory().create(ChainType.AlgorandV1, [{ url: null }])
    const prviateKeyToEncrypt = 'private-key-to-recover'
    const recoverAndReencryptParams: any = {
      chainType: 'algorand',
      symmetricOptionsForReencrypt: { ...global.SYMMETRIC_ED25519_OPTIONS },
    }
    const transportPublicKey = await getTransportKey()

    // encrypt a payload using our public key - in this example, its a private key we've 'backed-up'
    const privateKeyToRecover = await chain.encryptWithPublicKey(prviateKeyToEncrypt, global.ALGO_PUB_KEY)
    // wrap the encrypted payload with the transport public key
    recoverAndReencryptParams.encryptedTransportEncrypted = await encryptWithTransportKey(
      privateKeyToRecover,
      transportPublicKey,
    )
    // encrypt the private keys we'll use to decrypt the privateKeyToRecover
    const encryptedPrivateKey = JSON.stringify(
      Crypto.Asymmetric.encryptWithPublicKey(global.BASE_PUBLIC_KEY, global.ALGO_PRIVATE_KEY),
    )

    // wrap the encrypted keys with the transport public key
    recoverAndReencryptParams.asymmetricEncryptedPrivateKeys = [encryptedPrivateKey]
    // wrap password with the transport public key
    recoverAndReencryptParams.symmetricOptionsForReencrypt.transportEncryptedPassword = await encryptWithTransportKey(
      global.MY_PASSWORD,
      transportPublicKey,
    )

    supertest(server)
      .post('/recover-and-reencrypt')
      .set(headers)
      .send({ ...recoverAndReencryptParams })
      .expect('Content-Type', /json/)
      .expect(200)
      .end(async (err, res) => {
        if (err) return done(err)
        const decryptedString = chain.decryptWithPassword(
          res.body.symmetricEncryptedString,
          global.MY_PASSWORD,
          global.SYMMETRIC_ED25519_OPTIONS,
        )
        expect(decryptedString).toMatch(prviateKeyToEncrypt)
        done()
      })
  })

  it('should throw error for missing asymmetricEncryptedPrivateKeys and asymmetricTransportEncryptedPrivateKeys', async done => {
    const chain = new ChainFactory().create(ChainType.AlgorandV1, [{ url: null }])
    const prviateKeyToEncrypt = 'private-key-to-recover'
    const recoverAndReencryptParams: any = {
      chainType: 'algorand',
      symmetricOptionsForReencrypt: { ...global.SYMMETRIC_ED25519_OPTIONS },
    }
    const transportPublicKey = await getTransportKey()

    // encrypt a payload using our public key - in this example, its a private key we've 'backed-up'
    const privateKeyToRecover = await chain.encryptWithPublicKey(prviateKeyToEncrypt, global.ALGO_PUB_KEY)
    // wrap the encrypted payload with the transport public key
    recoverAndReencryptParams.encryptedTransportEncrypted = await encryptWithTransportKey(
      privateKeyToRecover,
      transportPublicKey,
    )
    // encrypt the private keys we'll use to decrypt the privateKeyToRecover
    const encryptedPrivateKey = JSON.stringify(
      Crypto.Asymmetric.encryptWithPublicKey(global.BASE_PUBLIC_KEY, global.ALGO_PRIVATE_KEY),
    )
    // wrap password with the transport public key
    recoverAndReencryptParams.symmetricOptionsForReencrypt.transportEncryptedPassword = await encryptWithTransportKey(
      global.MY_PASSWORD,
      transportPublicKey,
    )

    supertest(server)
      .post('/recover-and-reencrypt')
      .set(headers)
      .send({ ...recoverAndReencryptParams })
      .expect('Content-Type', /json/)
      .expect(400)
      .end(async (err, res) => {
        if (err) return done(err)
        expect(res.body?.errorCode).toMatch('api_bad_parameter')
        expect(res.body?.errorMessage).toContain(
          'Missing at least one of these parameters in request body: asymmetricTransportEncryptedPrivateKeys, asymmetricEncryptedPrivateKeys',
        )
        done()
      })
  })

  it('should throw password missing error', async done => {
    const chain = new ChainFactory().create(ChainType.AlgorandV1, [{ url: null }])
    const prviateKeyToEncrypt = 'private-key-to-recover'
    const recoverAndReencryptParams: any = {
      chainType: 'algorand',
      symmetricOptionsForReencrypt: { ...global.SYMMETRIC_ED25519_OPTIONS },
    }
    const transportPublicKey = await getTransportKey()

    // encrypt a payload using our public key - in this example, its a private key we've 'backed-up'
    const privateKeyToRecover = await chain.encryptWithPublicKey(prviateKeyToEncrypt, global.ALGO_PUB_KEY)
    // wrap the encrypted payload with the transport public key
    recoverAndReencryptParams.encryptedTransportEncrypted = await encryptWithTransportKey(
      privateKeyToRecover,
      transportPublicKey,
    )
    // encrypt the private keys we'll use to decrypt the privateKeyToRecover
    const encryptedPrivateKey = JSON.stringify(
      Crypto.Asymmetric.encryptWithPublicKey(global.BASE_PUBLIC_KEY, global.ALGO_PRIVATE_KEY),
    )

    // wrap the encrypted keys with the transport public key
    recoverAndReencryptParams.asymmetricTransportEncryptedPrivateKeys = await encryptWithTransportKey(
      encryptedPrivateKey,
      transportPublicKey,
    )

    supertest(server)
      .post('/recover-and-reencrypt')
      .set(headers)
      .send({ ...recoverAndReencryptParams })
      .expect('Content-Type', /json/)
      .expect(400)
      .end(async (err, res) => {
        if (err) return done(err)
        expect(res.body?.errorCode).toMatch('api_bad_parameter')
        expect(res.body?.errorMessage).toContain(
          'Symmetric options were provided but missing either password or transportEncryptedPassword',
        )
        done()
      })
  })
})
