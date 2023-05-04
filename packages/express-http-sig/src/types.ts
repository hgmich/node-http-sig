// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import { Handler } from 'express'
import { Options } from 'body-parser'
import { HttpSigParams } from '@holmesmr/http-sig'

export { ConfigurationError } from '@holmesmr/http-sig'

export type HttpSigMiddlewareParams = HttpSigParams

export type HttpSigHandler = {
  responseSigner: Handler
  requestSigEnforcer: Handler
  digestRequestBody: Options['verify']
}
