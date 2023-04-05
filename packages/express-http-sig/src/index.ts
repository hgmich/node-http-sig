import { ConfigurationError, createSignatureHandler, KeyWrapper, VerificationError } from '@holmesmr/http-sig'
import { MessageContext } from '@holmesmr/http-sig/lib/MessageContext'
import { NextFunction, Request, Response } from 'express'
import { HttpSigHandler, HttpSigMiddlewareParams } from './types'

export * from './types'

type RequestVerifyContext = {
  digest: Buffer
  key: KeyWrapper
}

export function requestMessageContext(req: Request): MessageContext {
  const ctx = new MessageContext()

  ctx.requestTarget({ method: req.method, path: req.path })

  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue
    if (Array.isArray(value)) {
      value.forEach((v) => ctx.header(name, v))
    } else {
      ctx.header(name, value)
    }
  }

  return ctx
}

export function responseMessageContext(res: Response): MessageContext {
  const ctx = new MessageContext()

  for (const [name, value] of Object.entries(res.getHeaders())) {
    if (value === undefined) continue
    if (Array.isArray(value)) {
      value.forEach((v) => ctx.header(name, v))
    } else {
      ctx.header(name, typeof value === 'string' ? value : value.toString())
    }
  }

  return ctx
}

export function httpSignatures(config: HttpSigMiddlewareParams): HttpSigHandler {
  const httpSig = createSignatureHandler(config)
  const keyId = 'foo'
  const bodyDigestKey = Symbol('bodyDigest')

  const requestSigEnforcer = (req: Request, res: Response, next: NextFunction) => {
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
    const key = httpSig.getKey(keyId)

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
        const digest = key.digest(buf).toString('base64')

        finalRes.set('Digest', `${key.digestAlgorithm}=${digest}`)

        const ctx = responseMessageContext(res)
        console.log('sig string:', ctx.signatureString(['(request-target)', 'Digest']))

        return realSend(body)
      }

    res.send = sendInterceptor(res, res.send) as any

    next()
  }

  const digestRequestBody = (req: Request, res: Response, buf: Buffer, _encoding: string) => {
    const key = httpSig.getKey(keyId)
    const computed = key.digest(buf)
    const context: RequestVerifyContext = {
      digest: computed,
      key,
    }

    // Needed to allow use of unique symbol w/ locals
    const locals = res.locals as any
    locals[bodyDigestKey] = context
  }

  return {
    responseSigner,
    digestRequestBody,
    requestSigEnforcer,
  }
}

export default httpSignatures
