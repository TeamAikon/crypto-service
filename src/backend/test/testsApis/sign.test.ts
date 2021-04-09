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
  getTransportKey,
  encryptWithTransportKey,
} from '../helpers'
import { setupGlobalConstants } from '../config/constants'

declare let global: any

const headers: any = {
  'api-key': global.TEST_APP_API_KEY,
  'Content-Type': 'application/json',
  Accept: 'application/json',
}
const toSign = '0xff703f9324c38fbb991ad56446990bc65b8d915fdf731bb0e9d8c3967bd7ef18'
const apiUrl = `${global.TEST_SERVER_PATH}/sign`
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

describe('Test api /sign endpoint', () => {
  jest.setTimeout(10000)

  it('asymmetricTransportEncryptedPrivateKeys: should return 200 & return signed string for ALGORANDV1', async done => {
    const transportPublicKey = await getTransportKey()
    const signParams: any = {
      toSign,
      transportPublicKey,
    }

    const chain = new ChainFactory().create(ChainType.AlgorandV1, [{ url: null }])
    signParams.chainType = chain.chainType

    const encryptedPrivateKey = JSON.stringify([
      Crypto.Asymmetric.encryptWithPublicKey(global.BASE_PUBLIC_KEY, global.ALGO_PRIVATE_KEY),
    ])
    signParams.asymmetricTransportEncryptedPrivateKeys = await encryptWithTransportKey(
      encryptedPrivateKey,
      transportPublicKey,
    )

    supertest(server)
      .post('/sign')
      .set(headers)
      .send({ ...signParams })
      .expect('Content-Type', /json/)
      .expect(200)
      .end(async (err, res) => {
        if (err) return done(err)
        expect(res.body[0]).toMatch(
          '7fe17a4408cad898b2943152e39b2640b9a0e20e2c903169dd879cbea39b9762e6c208e2573108f670ae99e4114e37713a59c16ff371d5f11b6c65ed82633002',
        )
        done()
      })
  })

  it('asymmetricEncryptedPrivateKeys: should return 200 & return signed string for ALGORANDV1', async done => {
    const transportPublicKey = await getTransportKey()
    const signParams: any = {
      toSign,
      transportPublicKey,
    }

    const chain = new ChainFactory().create(ChainType.AlgorandV1, [{ url: null }])
    signParams.chainType = chain.chainType

    const encryptedPrivateKey = JSON.stringify([
      Crypto.Asymmetric.encryptWithPublicKey(global.BASE_PUBLIC_KEY, global.ALGO_PRIVATE_KEY),
    ])
    signParams.asymmetricEncryptedPrivateKeys = [encryptedPrivateKey]

    supertest(server)
      .post('/sign')
      .set(headers)
      .send({ ...signParams })
      .expect('Content-Type', /json/)
      .expect(200)
      .end(async (err, res) => {
        if (err) return done(err)
        expect(res.body[0]).toMatch(
          '7fe17a4408cad898b2943152e39b2640b9a0e20e2c903169dd879cbea39b9762e6c208e2573108f670ae99e4114e37713a59c16ff371d5f11b6c65ed82633002',
        )
        done()
      })
  })

  it('should return 200 & return signed string for ALGORANDV1', async done => {
    const transportPublicKey = await getTransportKey()
    const signParams: any = {
      toSign,
      symmetricOptions: { ...global.SYMMETRIC_AES_OPTIONS },
      transportPublicKey,
    }

    const chain = new ChainFactory().create(ChainType.AlgorandV1, [{ url: null }])
    signParams.chainType = chain.chainType
    signParams.symmetricEncryptedPrivateKeys = [
      chain.encryptWithPassword(global.ALGO_PRIVATE_KEY, global.MY_PASSWORD, global.SYMMETRIC_AES_OPTIONS),
    ]
    const transportEncryptedPassword = await encryptWithTransportKey(global.MY_PASSWORD, transportPublicKey)
    signParams.symmetricOptions.transportEncryptedPassword = transportEncryptedPassword

    supertest(server)
      .post('/sign')
      .set(headers)
      .send({ ...signParams })
      .expect('Content-Type', /json/)
      .expect(200)
      .end(async (err, res) => {
        if (err) return done(err)
        expect(res.body[0]).toMatch(
          '7fe17a4408cad898b2943152e39b2640b9a0e20e2c903169dd879cbea39b9762e6c208e2573108f670ae99e4114e37713a59c16ff371d5f11b6c65ed82633002',
        )
        done()
      })
  })

  it('should return 200 & return signed string for EOSV2', async done => {
    const transportPublicKey = await getTransportKey()
    const signParams: any = {
      toSign,
      symmetricOptions: { ...global.SYMMETRIC_AES_OPTIONS },
    }
    const chain = new ChainFactory().create(ChainType.EosV2, [{ url: null }])
    signParams.chainType = chain.chainType
    signParams.symmetricEncryptedPrivateKeys = [
      chain.encryptWithPassword(global.EOS_PRIVATE_KEY, global.MY_PASSWORD, global.SYMMETRIC_AES_OPTIONS),
    ]
    const transportEncryptedPassword = await encryptWithTransportKey(global.MY_PASSWORD, transportPublicKey)
    signParams.symmetricOptions.transportEncryptedPassword = transportEncryptedPassword

    supertest(server)
      .post('/sign')
      .set(headers)
      .send({ ...signParams })
      .expect('Content-Type', /json/)
      .expect(200)
      .end(async (err, res) => {
        if (err) return done(err)
        expect(res.body[0]).toMatch(
          'SIG_K1_JukVtvPxWFYYCGut6VFEhUr5dWo2KEDzTZsePKzpb3RB6Tj7h81kNqg3NW1AD1aEFKsRBqKoXfCA2Hy2KAkJF1x4exoL6j',
        )
        done()
      })
  })
  it('should return 200 & return signed string for ETHEREUM', async done => {
    const transportPublicKey = await getTransportKey()
    const signParams: any = {
      toSign,
      symmetricOptions: { ...global.SYMMETRIC_AES_OPTIONS },
    }
    const chain = new ChainFactory().create(ChainType.EthereumV1, [{ url: null }])
    signParams.chainType = chain.chainType
    signParams.symmetricEncryptedPrivateKeys = [
      chain.encryptWithPassword(global.ETH_PPRIVATE_KEY, global.MY_PASSWORD, global.SYMMETRIC_AES_OPTIONS),
    ]
    const transportEncryptedPassword = await encryptWithTransportKey(global.MY_PASSWORD, transportPublicKey)
    signParams.symmetricOptions.transportEncryptedPassword = transportEncryptedPassword

    supertest(server)
      .post('/sign')
      .set(headers)
      .send({ ...signParams })
      .expect('Content-Type', /json/)
      .expect(200)
      .end(async (err, res) => {
        if (err) return done(err)
        expect(JSON.stringify(res.body[0])).toMatch(
          '{"r":{"type":"Buffer","data":[206,254,43,20,99,179,91,1,74,35,188,4,247,57,128,42,87,110,133,25,181,237,94,209,91,99,5,5,227,142,84,79]},"s":{"type":"Buffer","data":[102,248,52,15,89,161,138,91,142,131,4,173,251,179,0,112,107,89,110,96,47,111,128,141,91,61,117,210,211,139,68,47]},"v":27}',
        )
        done()
      })
  })

  it('should throw an error for missing password', async done => {
    const transportPublicKey = await getTransportKey()
    const signParams: any = {
      toSign,
      symmetricOptions: { ...global.SYMMETRIC_AES_OPTIONS },
      transportPublicKey,
    }

    const chain = new ChainFactory().create(ChainType.AlgorandV1, [{ url: null }])
    signParams.chainType = chain.chainType
    signParams.symmetricEncryptedPrivateKeys = [
      chain.encryptWithPassword(global.ALGO_PRIVATE_KEY, global.MY_PASSWORD, global.SYMMETRIC_AES_OPTIONS),
    ]

    supertest(server)
      .post('/sign')
      .set(headers)
      .send({ ...signParams })
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
