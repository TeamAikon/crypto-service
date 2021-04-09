/* eslint-disable consistent-return */
/* eslint-disable jest/no-done-callback */
import supertest from 'supertest'
import { Server } from 'http'
import { ChainFactory, ChainType } from '@open-rights-exchange/chainjs'
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
const apiUrl = `${global.TEST_SERVER_PATH}/generate-keys`
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

describe('Test api /generate-keys endpoint', () => {
  jest.setTimeout(10000)

  it('should return 200 & return generated keys', async done => {
    const transportPublicKey = await getTransportKey()
    const myPassword = 'my-secure-password'
    const symmetricAesOptions = {
      salt: 'my-salt',
      iter: 50000,
    }
    const generateKeyParams: any = {
      chainType: 'ethereum',
      symmetricOptions: symmetricAesOptions,
      transportPublicKey,
    }
    const transportEncryptedPassword = await encryptWithTransportKey(global.MY_PASSWORD, transportPublicKey)
    generateKeyParams.symmetricOptions.transportEncryptedPassword = transportEncryptedPassword

    const chain = new ChainFactory().create(ChainType.EthereumV1, [{ url: null }])
    supertest(server)
      .post('/generate-keys')
      .set(headers)
      .send({ ...generateKeyParams })
      .expect('Content-Type', /json/)
      .expect(200)
      .end((err, res) => {
        if (err) return done(err)
        const encryptedPrivateKey = res.body[0].symmetricEncryptedString
        const newPrivateKey = chain.decryptWithPassword(encryptedPrivateKey, myPassword, symmetricAesOptions)
        expect(chain.isValidPublicKey(res.body[0].publicKey).toString()).toMatch('true')
        expect(chain.isValidPrivateKey(newPrivateKey).toString()).toMatch('true')
        done()
      })
  })

  it('should return 200 & return 4 generated keys: Check the loop count', async done => {
    const transportPublicKey = await getTransportKey()
    const myPassword = 'my-secure-password'
    const symmetricAesOptions = {
      salt: 'my-salt',
      iter: 50000,
    }
    const generateKeyParams: any = {
      chainType: 'ethereum',
      symmetricOptions: symmetricAesOptions,
      transportPublicKey,
      keyCount: 4,
    }
    const transportEncryptedPassword = await encryptWithTransportKey(global.MY_PASSWORD, transportPublicKey)
    generateKeyParams.symmetricOptions.transportEncryptedPassword = transportEncryptedPassword

    const chain = new ChainFactory().create(ChainType.EthereumV1, [{ url: null }])
    supertest(server)
      .post('/generate-keys')
      .set(headers)
      .send({ ...generateKeyParams })
      .expect('Content-Type', /json/)
      .expect(200)
      .end((err, res) => {
        if (err) return done(err)
        // eslint-disable-next-line no-plusplus
        for (let a = 0; a < 4; a++) {
          expect(res.body[a]).toMatchObject({})
          const encryptedPrivateKey = res.body[a].symmetricEncryptedString
          const newPrivateKey = chain.decryptWithPassword(encryptedPrivateKey, myPassword, symmetricAesOptions)
          expect(chain.isValidPublicKey(res.body[0].publicKey).toString()).toMatch('true')
          expect(chain.isValidPrivateKey(newPrivateKey).toString()).toMatch('true')
        }
        done()
      })
  })

  it('should return 200 & return generated keys and should contain asym and sym valid options', async done => {
    const transportPublicKey = await getTransportKey()
    const myPassword = 'my-secure-password'
    const symmetricAesOptions = {
      salt: 'my-salt',
      iter: 50000,
    }
    const generateKeyParams: any = {
      chainType: 'ethereum',
      symmetricOptions: symmetricAesOptions,
      asymmetricOptions: [
        {
          publicKeys: [global.ETH_PUB_KEY],
        },
      ],
      keyCount: 4,
      transportPublicKey,
    }

    const transportEncryptedPassword = await encryptWithTransportKey(global.MY_PASSWORD, transportPublicKey)
    generateKeyParams.symmetricOptions.transportEncryptedPassword = transportEncryptedPassword
    
    const chain = new ChainFactory().create(ChainType.EthereumV1, [{ url: null }])
    supertest(server)
      .post('/generate-keys')
      .set(headers)
      .send({ ...generateKeyParams })
      .expect('Content-Type', /json/)
      .expect(200)
      .end(async (err, res) => {
        if (err) return done(err)
        const encryptedPrivateKey = res.body[0].symmetricEncryptedString
        const newPrivateKey = chain.decryptWithPassword(encryptedPrivateKey, myPassword, symmetricAesOptions)
        const asymEncryptedPrivateKey = JSON.parse(res.body[0].asymmetricEncryptedStrings[0])[0]
        const decryptedPrivateKey = await chain.decryptWithPrivateKey(asymEncryptedPrivateKey, global.ETH_PPRIVATE_KEY)
        expect(newPrivateKey).toMatch(decryptedPrivateKey)
        expect(chain.isValidPublicKey(res.body[0].publicKey).toString()).toMatch('true')
        expect(chain.isValidPrivateKey(newPrivateKey).toString()).toMatch('true')
        done()
      })
  })
})
