// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import { ConfigurationError, SignatureKeyManager, SignatureKey, Signature } from '@holmesmr/http-sig'
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Inject,
  RawBodyRequest,
  StreamableFile,
} from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Request, Response } from 'express'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'
import { SIGNED_KEY, SignedEndpointOptions } from '../decorators/signed.decorator'
import { SIGNATURE_INST } from '../constants'
import { getLastOrOnly } from '../common'
import { requestMessageWrapper, responseMessageWrapper } from '../message-wrappers'

const isJson = (s: any) => typeof s === 'object' && !Buffer.isBuffer(s) && !(s instanceof StreamableFile)

@Injectable()
export class SignResponseInterceptor implements NestInterceptor {
  constructor(@Inject(SIGNATURE_INST) private sig: SignatureKeyManager, private reflector: Reflector) {}

  async intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<any>> {
    const endpointOpts = this.reflector.getAllAndOverride<SignedEndpointOptions | undefined>(SIGNED_KEY, [
      context.getHandler(),
      context.getClass(),
    ])

    // Terminate if the request isn't being signed
    if (!endpointOpts || !endpointOpts.signResponse) return next.handle()

    const req = context.switchToHttp().getRequest<RawBodyRequest<Request>>()

    // The signature is needed because the default action is to respond with the same keyId as received
    const messageCtx = requestMessageWrapper(req)
    const signature = messageCtx.getSignature()
    let keyId = endpointOpts?.keyId

    // Only try to backfill keyId if the signature is actually intended to be verified
    // and if an override is not provided
    if ((!endpointOpts || endpointOpts.verifyRequest) && signature && !keyId) {
      // Default to using same keyId as provided in request
      keyId = signature.keyId
    }
    if (!keyId) throw new ConfigurationError('unable to determine keyId for request')

    // We can now retrieve the key
    const key = await this.sig.getKey(keyId)

    // move onto handling wrapping the response
    return next.handle().pipe(
      map((data) => {
        const res = context.switchToHttp().getResponse<Response>()

        return this.handleResponse(data, res, key)
      }),
    )
  }

  private handleResponse(data: any, res: Response, key: SignatureKey): any {
    let outData = data
    if (key.options.calculateDigest && data !== undefined) {
      const contentType = getLastOrOnly(res.getHeader('Content-Type'))?.toString()

      // TODO: more robust serialization of body
      if (
        (contentType && (contentType === 'application/json' || contentType.startsWith('application/json; '))) ||
        isJson(data)
      ) {
        outData = Buffer.from(JSON.stringify(data), 'utf8')
        if (!contentType) res.setHeader('Content-Type', 'application/json; charset=utf-8')
      } else if (!Buffer.isBuffer(data)) {
        outData = Buffer.from(data.toString(), 'utf8')
        if (!contentType) res.setHeader('Content-Type', 'text/plain')
      }

      const digest = key.createDigestHeader(outData)
      res.setHeader('Digest', digest)
      outData = new StreamableFile(outData)
    }

    const msgCtx = responseMessageWrapper(res)
    const signature = key.signResponse(msgCtx)

    res.setHeader('Signature', signature)

    return outData
  }
}
