import { Handler } from 'express'
import { Options } from 'body-parser'
import { HttpSigParams } from '@moodysanalytics/http-sig'

export { ConfigurationError } from '@moodysanalytics/http-sig'

export type HttpSigMiddlewareParams = HttpSigParams

export type HttpSigHandler = {
  responseSigner: Handler
  requestSigEnforcer: Handler
  digestRequestBody: Options['verify']
}
