// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import { SetMetadata } from '@nestjs/common'
export const SIGNED_KEY = 'signedHttpMessages'

export type SignedEndpointOptions = {
  verifyRequest: boolean
  signResponse: boolean
  keyId?: string
}

const DEFAULT_OPTIONS = Object.freeze({
  verifyRequest: true,
  signResponse: true,
})

function valueOrDefault<T extends object, K extends keyof T>(key: K, vals: Partial<T>, defaultVals: T): T[K] {
  const value = vals[key]
  const defValue = defaultVals[key]
  return value !== undefined && value !== null ? value : defValue
}

export const Signed = (opts?: Partial<SignedEndpointOptions>) =>
  SetMetadata(
    SIGNED_KEY,
    opts
      ? {
          keyId: opts.keyId,
          verifyRequest: valueOrDefault('verifyRequest', opts, DEFAULT_OPTIONS),
          signResponse: valueOrDefault('signResponse', opts, DEFAULT_OPTIONS),
        }
      : DEFAULT_OPTIONS,
  )
