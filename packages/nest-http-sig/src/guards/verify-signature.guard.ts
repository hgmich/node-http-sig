// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import { ConfigurationError, Signature, SignatureKeyManager, VerificationError } from '@holmesmr/http-sig'
import { CanActivate, ExecutionContext, ForbiddenException, Inject, Injectable, RawBodyRequest } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Request } from 'express'
import { SIGNATURE_INST } from '../constants'
import { SIGNED_KEY, SignedEndpointOptions } from '../decorators/signed.decorator'
import { requestMessageWrapper } from '../message-wrappers'
import { getLastOrOnly, getSignatureString } from '../common'

const isEmptyBody = (body: any): boolean => !body || (typeof body === 'object' && Object.keys(body).length === 0)

@Injectable()
export class VerifySignatureGuard implements CanActivate {
  constructor(@Inject(SIGNATURE_INST) private sig: SignatureKeyManager, private reflector: Reflector) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      return await this.canActivateInner(context)
    } catch (e) {
      if (e instanceof VerificationError) {
        throw new ForbiddenException('signature verification failed', { cause: e })
      } else {
        throw e
      }
    }
  }

  private async canActivateInner(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<RawBodyRequest<Request>>()

    const endpointOpts = this.reflector.getAllAndOverride<SignedEndpointOptions | undefined>(SIGNED_KEY, [
      context.getHandler(),
      context.getClass(),
    ])

    // If the @Signed() decorator is not added to the endpoint,
    // or if signature verification isn't requested, don't proceed
    if (!endpointOpts || !endpointOpts.verifyRequest) {
      return true
    }

    // Detect incorrect configuration before proceeding
    if (!isEmptyBody(req.body) && !req.rawBody) {
      throw new ConfigurationError('rawBody missing from request (set rawBody: true in NestFactory.create)')
    }

    const sigStr = getSignatureString(req)

    if (!sigStr) throw new VerificationError('signature not present on request')

    // Prepare signature for verification
    const signature = Signature.fromHeader(sigStr)
    const key = await this.sig.getKey(signature.keyId)
    const messageCtx = key.createMessageContext(requestMessageWrapper(req))

    // Verify signature
    const sigVerified = key.verifyRequest(messageCtx)
    if (!sigVerified) throw new VerificationError('signature verification failed')

    // If requested, verify body against digest
    if (req.rawBody && signature.headers.includes('digest')) {
      const digestHeader = getLastOrOnly(req.headers.digest)
      if (!digestHeader) throw new VerificationError('digest required for requests with bodies')

      const digestVerified = key.verifyDigestHeader(req.rawBody, digestHeader)
      if (!digestVerified) throw new VerificationError('digest verification failed')
    } else if (!req.body && req.headers.digest) {
      throw new VerificationError('digest provided for request with no body')
    }

    return true
  }
}
