// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import {
  ConfigurationError,
  signatures,
  SignatureKey,
  VerificationError,
  createMessageContext,
  MessageContext,
} from '@holmesmr/http-sig'
import { NextFunction, Request, Response } from 'express'
import { HttpSigHandler, HttpSigMiddlewareParams } from './types'

export * from './types'

type RequestVerifyContext = {
  digestMatch?: boolean
  key: SignatureKey
}

export function requestMessageWrapper(req: Request): MessageContext {
  return createMessageContext({
    requestTarget: { method: req.method, path: req.path },
    getHeader(name: string) {
      const header = req.headers[name]
      if (typeof header === 'string') {
        return [header]
      }

      return header
    },
  })
}

export function responseMessageWrapper(res: Response): MessageContext {
  return createMessageContext({
    getHeader(name: string) {
      const header = res.getHeader(name)
      if (typeof header === 'string') {
        return [header]
      } else if (typeof header === 'number') {
        return [header.toString()]
      }

      return header
    },
  })
}

function getLastOrOnly<T>(xs: T | T[] | undefined): T | undefined {
  return Array.isArray(xs) ? xs.slice(-1)[0] : xs
}

export function httpSignatures(config: HttpSigMiddlewareParams): HttpSigHandler {
  const httpSig = signatures(config)
  const keyId = 'foo'
  const bodyDigestKey = Symbol('bodyDigest')

  const requestSigEnforcer = (req: Request, res: Response, next: NextFunction) => {
    // abandon request if no signature present
    if (!req.headers.signature) throw new VerificationError('request was not signed')

    // Needed to allow use of unique symbol w/ locals
    const locals = res.locals as any
    const verifyCtx = locals[bodyDigestKey] as RequestVerifyContext | undefined
    const parsed = Boolean((req as any)._body)

    if (!verifyCtx && parsed) throw new ConfigurationError('bodyParser was used without the digestRequestBody helper')

    // Reuse context from verification step if possible
    const key = verifyCtx?.key || httpSig.getKey(keyId)

    next()
  }

  const responseSigner = (req: Request, res: Response, next: NextFunction) => {
    httpSig.getKey(keyId).then((key) => {
      const sendInterceptor = (finalRes: Response, send: NextFunction) =>
        function (this: any, body: any) {
          const realSend = send.bind(this as any)

          // Cannot sign requests already being sent
          if (res.headersSent) throw new ConfigurationError('cannot sign request already in process')

          // Rerun through res.json() if not string or Buffer
          if (!(typeof body === 'string' || body instanceof Buffer)) {
            return finalRes.json(body)
          }

          const buf = body instanceof Buffer ? body : Buffer.from(body, 'utf-8')

          finalRes.set('Digest', key.createDigestHeader(buf))

          const ctx = responseMessageWrapper(res)
          const sig = key.signResponse(ctx)

          finalRes.set('Signature', sig)

          return realSend(body)
        }

      res.send = sendInterceptor(res, res.send) as any

      next()
    })
  }

  const digestRequestBody = (req: Request, res: Response, buf: Buffer, _encoding: string) => {
    httpSig.getKey(keyId).then((key) => {
      let digestMatch
      if (key.options.calculateDigest) {
        // Get the last digest header if multiple set
        const digestHeader = getLastOrOnly(req.headers.digest)

        // Require that the digest header be set
        if (!digestHeader) throw new VerificationError('request digest not set')

        digestMatch = key.verifyDigestHeader(buf, digestHeader)
      }
      const context: RequestVerifyContext = {
        digestMatch,
        key,
      }

      // Needed to allow use of unique symbol w/ locals
      const locals = res.locals as any
      locals[bodyDigestKey] = context
    })
  }

  return {
    responseSigner,
    digestRequestBody,
    requestSigEnforcer,
  }
}

export default httpSignatures
