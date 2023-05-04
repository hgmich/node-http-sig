// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import { VerificationError } from '@holmesmr/http-sig'
import { RawBodyRequest } from '@nestjs/common'
import { Request } from 'express'

export function getLastOrOnly<T>(xs: T | T[] | undefined): T | undefined {
  return Array.isArray(xs) ? xs.slice(-1)[0] : xs
}

export function getSignatureString(req: RawBodyRequest<Request>): string | undefined {
  if (Array.isArray(req.headers.signature)) {
    if (req.headers.signature.length > 1) throw new VerificationError('multiple signatures present on request')
    return req.headers.signature[0]
  }

  return req.headers.signature
}
