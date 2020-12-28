import { Request, Response } from 'express'
import url from 'url'
import { generateProcessId, Logger, isNullOrEmpty, isAString } from 'aikon-js'
import dotenv from 'dotenv'
import { analyticsEvent } from '../services/segment/resolvers'
import { rollbar } from '../services/rollbar/connectors'
import {
  AnalyticsEvent,
  AppId,
  AuthTokenType,
  Context,
  ErrorType,
  HttpStatusCode,
  SymmetricOptionsParam,
} from '../models'
import { composeErrorResponse, ServiceError } from '../resolvers/errors'
import { getAppIdFromApiKey } from '../resolvers/appRegistration'
import { validateAuthTokenAndExtractContents } from '../resolvers/token'

dotenv.config()

const settingTracingEnabled = true // TODO: Move this to runtime settings

// ---- Helper functions

const getOrCreateProcessId = (req: Request) => {
  return (req.headers['process-id'] as string) || generateProcessId()
}

export const getProcessIdAndLogger = (req: Request) => {
  const processId = getOrCreateProcessId(req)
  const logger = new Logger({ rollbar, processId, tracingEnabled: settingTracingEnabled })
  return { processId, logger }
}

export function createContext(req: Request, appId?: AppId): Context {
  const { logger, processId } = getProcessIdAndLogger(req)
  const context = { appId, logger, processId }
  return context
}

/** use request headers to determine appId, serviceID, and processId
 * also creates a context object from these values */
export async function getAppIdAndContextFromApiKey(req: Request) {
  // this context can be passed to mutations that update the database
  const context = createContext(req)
  const { logger } = context

  // appId
  const appId = await getAppIdFromApiKey(req.headers['api-key'] as string, context)
  if (isNullOrEmpty(appId)) {
    throw new ServiceError(
      'Missing required header parameter: api-key',
      ErrorType.BadParam,
      'getAppIdAndContextFromApiKey',
    )
  }

  context.appId = appId
  logger.trace(`getAppIdAndContext got appId ${appId}`)

  return { appId, context }
}

/** check the url's query params for each required param in paramNames */
export function checkForRequiredParams(req: Request, paramNames: any[], funcName: string) {
  const missing: any = []
  paramNames.forEach(p => {
    if (isNullOrEmpty(req.query[p])) {
      missing.push(p)
    }
  })
  if (!isNullOrEmpty(missing)) {
    throw new ServiceError(`Missing required parameter(s): ${missing.join(', ')}`, ErrorType.BadParam, funcName)
  }
}

/** check the header of the request for each required param in paramNames */
export function checkHeaderForRequiredValues(req: Request, paramNames: any[], funcName: string) {
  const missing: any[] = []
  paramNames.forEach(p => {
    if (isNullOrEmpty(req.headers[p])) {
      missing.push(p)
    }
  })
  if (!isNullOrEmpty(missing)) {
    throw new ServiceError(
      `Missing required parameter(s) in request header: ${missing.join(', ')}`,
      ErrorType.BadParam,
      funcName,
    )
  }
}

/** check the body of the request for each required param in paramNames */
export function checkBodyForRequiredValues(req: Request, paramNames: any[], funcName: string) {
  const missing: any[] = []
  paramNames.forEach(p => {
    if (isNullOrEmpty(req.body[p])) {
      missing.push(p)
    }
  })
  if (!isNullOrEmpty(missing)) {
    throw new ServiceError(
      `Missing required parameter(s) in request body: ${missing.join(', ')}`,
      ErrorType.BadParam,
      funcName,
    )
  }
}

/** check the body of the request - must include at least one of the params in the list */
export function checkBodyForAtLeastOneOfValues(req: Request, paramNames: any[], funcName: string) {
  const matches = paramNames.filter(p => {
    return !isNullOrEmpty(req.body[p])
  })
  if (matches.length === 0) {
    throw new ServiceError(
      `Missing at least one of these parameters in request body: ${paramNames.join(', ')}`,
      ErrorType.BadParam,
      funcName,
    )
  }
}

/** check the body of the request - must include one and only one of params in the list */
export function checkBodyForOnlyOneOfValues(req: Request, paramNames: any[], funcName: string) {
  const matches = paramNames.filter(p => {
    return !isNullOrEmpty(req.body[p])
  })
  if (matches.length > 1) {
    throw new ServiceError(
      `You can only provide one of these parameters in request body: ${paramNames.join(', ')}`,
      ErrorType.BadParam,
      funcName,
    )
  }
}

/** Helper to log analytics for an API request */
export function analyticsForApi(req: Request, data: any, context: Context) {
  const path = req.baseUrl
  // TODO: Replace depricated api (url.parse)
  const { query } = url.parse(req.url) // eslint-disable-line
  analyticsEvent('api', AnalyticsEvent.ApiCalled, { path, query, ...data }, context)
}

/** Return response and log analytics */
export function returnResponse(
  req: Request,
  res: Response,
  httpStatusCode: number,
  responseToReturn: any,
  context: Context,
  error?: Error,
) {
  const { appId } = context || {}
  let errorResponse

  if (httpStatusCode !== HttpStatusCode.OK_200) {
    errorResponse = composeErrorResponse(context, error)
    responseToReturn = { ...errorResponse, ...responseToReturn }
  }
  // if no context provided, create one (in part, to get processId from request header)
  if (!context) {
    context = createContext(req)
  }
  analyticsForApi(req, { httpStatusCode, appId, errorResponse }, context)
  return res.status(httpStatusCode).json({ processId: context?.processId, ...responseToReturn })
}

/** Validate token helper - extacts info from request object */
export async function validatePasswordAuthToken(
  req: Request,
  symmetricOptions: SymmetricOptionsParam,
  /** principal value of function - e.g. for /sign, it the content toSign */
  bodyToVerify: any,
  context: Context,
) {
  if (isNullOrEmpty(symmetricOptions)) return null
  return validateAuthTokenAndExtractContents(
    AuthTokenType.Password,
    getFullUrlFromRequest(req),
    symmetricOptions?.passwordAuthToken, // base64 encoded
    bodyToVerify,
    context,
  )
}

/** Validate token helper - extacts info from request object */
export async function validateAuthToken(req: Request, context: Context) {
  return validateAuthTokenAndExtractContents(
    AuthTokenType.ApiHeader,
    getFullUrlFromRequest(req),
    req.headers['auth-token'] as string,
    req?.body,
    context,
  )
}

/** Compose the full url of the request */
export function getFullUrlFromRequest(req: Request) {
  return `${req.protocol}://${req.get('host')}${req.originalUrl}`
}
