import mongoose from 'mongoose'
import { Mongo } from '../../services/mongo/models'
import { connectToMongo } from '../../services/mongo/connectors'
import { countMongo, upsertMongo } from '../../services/mongo/resolvers'
import * as dbMocks from '../dbMocks'
import { Context } from '../../../models'
import { ContextTest } from '../config/globalMocks'

const MONGO_TIMEOUT = 15000

export const clearDB = async () => {
  await mongoose.connection.db.dropDatabase()
  // if you dont connect to the database first, the collection.drop() will return the promise but wont execute the drop until the next connection - causing errors
  // await openDB()
  // const collections = await mongoose.connection.db.collections()
  // await Promise.all(
  //   collections.map(async collection => {
  //     await collection.drop()
  //   }),
  // )
}

export const closeDB = async () => {
  await mongoose.disconnect()
}

export const openDB = async (connectionName = 'test') => {
  await connectToMongo(`mongodb://localhost:27017/${connectionName}`, MONGO_TIMEOUT)
}

type DatabaseIntializationData = {
  appRegistration?: any
  appConfig?: any
  authToken?: any
}

interface InitializeDBParams extends DatabaseIntializationData {
  context?: Context
}

export const initializeDB = async (params: InitializeDBParams = {}) => {
  const { context = ContextTest, appConfig, appRegistration, authToken } = params
  await clearDB()

  // Using promise.all to run in parallel
  await Promise.all([
    await upsertMongo({
      context,
      mongoObject: Mongo.AppConfig,
      newItem: dbMocks.appConfig(appConfig),
    }),
    await upsertMongo({
      context,
      mongoObject: Mongo.AppRegistration,
      newItem: dbMocks.appRegistration(appRegistration),
    }),
  ])
}
