// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import {
  ConcreteSignatureOptions,
  ConfigurationError,
  DigestAlgorithm,
  HmacAlgorithm,
  SecretKeyConfig,
  SignatureAlgorithm,
  VerificationError,
} from './types'
import { DigestFactory, SignatureKey } from './SignatureKey'
import * as crypto from 'crypto'

type HmacFactory = () => crypto.Hmac

export class HmacSignatureKey extends SignatureKey {
  private readonly hmac: HmacFactory
  readonly algorithm: HmacAlgorithm

  constructor(
    id: string,
    signatureAlgorithm: SignatureAlgorithm,
    hasher: DigestFactory,
    digest: DigestAlgorithm,
    config: SecretKeyConfig,
    opts: ConcreteSignatureOptions,
  ) {
    super(id, hasher, signatureAlgorithm, digest, opts)
    this.hmac = HmacSignatureKey.createHmacFactory(config)
    this.algorithm = config.algorithm
  }

  static createHmacFactory(config: SecretKeyConfig) {
    // Check correct key type used
    if (config.key.type !== 'secret')
      throw new ConfigurationError(`HMAC key type requires secret key, got ${config.key.type}`)
    const hmacFactory = (algorithm: string) => () => crypto.createHmac(algorithm, config.key)
    if (Object.values(HmacAlgorithm).includes(config.algorithm)) {
      switch (config.algorithm) {
        case HmacAlgorithm.SHA256:
          return hmacFactory('sha256')
        case HmacAlgorithm.SHA512:
          return hmacFactory('sha512')
      }
    } else {
      throw new ConfigurationError(`Unsupported HMAC algorithm ${config.algorithm}`)
    }
  }

  sign(buf: Buffer): Buffer {
    const hmac = this.hmac()
    hmac.write(buf)
    return hmac.digest()
  }

  verify({ buf, mac }: { buf: Buffer; mac: Buffer }): boolean {
    // create reference signature for comparison
    const actualMac = this.sign(buf)

    try {
      return crypto.timingSafeEqual(actualMac, mac)
    } catch (e) {
      if (e instanceof RangeError) {
        throw new VerificationError('signature length mismatch')
      }
      throw e
    }
  }
}
