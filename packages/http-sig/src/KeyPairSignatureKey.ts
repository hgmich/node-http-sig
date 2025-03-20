// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import {
  ConcreteSignatureOptions,
  ConfigurationError,
  DigestAlgorithm,
  KeyPairAlgorithm,
  KeyPairConfig,
  SignatureAlgorithm,
} from './types'
import { DigestFactory, SignatureKey } from './SignatureKey'
import * as crypto from 'crypto'

export type SignFactory = () => crypto.Sign
export type VerifyFactory = () => crypto.Verify

const SIG_TO_NODE_KEY_TYPE: { [Value in KeyPairAlgorithm]: crypto.KeyType } = {
  [KeyPairAlgorithm.RSA]: 'rsa',
  [KeyPairAlgorithm.ECDSA]: 'ec',
}

const NODE_TO_SIG_KEY_TYPE: { [Value in crypto.KeyType]?: KeyPairAlgorithm } = Object.fromEntries(
  Object.entries(SIG_TO_NODE_KEY_TYPE).map(([k, v]) => [v, k as KeyPairAlgorithm]),
)

type SignContext = {
  factory: SignFactory
  key: crypto.SignKeyObjectInput
}

type VerifyContext = {
  factory: VerifyFactory
  key: crypto.VerifyKeyObjectInput
}

export class KeyPairSignatureKey extends SignatureKey {
  private readonly verifyCtx: VerifyContext
  private readonly signCtx?: SignContext
  readonly algorithm: KeyPairAlgorithm

  constructor(
    id: string,
    hasher: DigestFactory,
    signatureAlgorithm: SignatureAlgorithm,
    digest: DigestAlgorithm,
    config: KeyPairConfig,
    opts: ConcreteSignatureOptions,
  ) {
    super(id, hasher, signatureAlgorithm, digest, opts)
    this.verifyCtx = KeyPairSignatureKey.createVerifyContext(config)
    this.signCtx = KeyPairSignatureKey.createSignContext(config)
    this.algorithm = config.keyAlgorithm
  }

  private static createVerifyContext(config: KeyPairConfig): VerifyContext {
    // Check correct key type used
    if (!config.publicKey.asymmetricKeyType || config.publicKey.type !== 'public')
      throw new ConfigurationError(`keypair public key type requires public key, got ${config.publicKey.type}`)

    // Get the equivalent node keypair algorithm for the signature scheme
    const actualSigKeyType = NODE_TO_SIG_KEY_TYPE[config.publicKey.asymmetricKeyType]

    // Reject keys of unknown type
    if (actualSigKeyType === undefined)
      throw new ConfigurationError(
        `keypair public key uses unsupported node crypto key type: ${config.publicKey.asymmetricKeyType}`,
      )
    // Reject keys of differing type to expectation
    if (actualSigKeyType !== config.keyAlgorithm)
      throw new ConfigurationError(
        `expected ${config.keyAlgorithm} public key, but got public key of type ${actualSigKeyType}`,
      )

    // Reject unknown signing hash algorithms
    if (!crypto.getHashes().includes(config.hashAlgorithm))
      throw new ConfigurationError(`keypair hash algorithm not supported: ${config.hashAlgorithm}`)

    // Handle key-type specific config options
    let key: crypto.VerifyKeyObjectInput = { key: config.publicKey }
    switch (config.keyAlgorithm) {
      case KeyPairAlgorithm.RSA:
        if (config.padding !== undefined) key.padding = config.padding
        if (config.saltLength !== undefined) key.saltLength = config.saltLength
        break
      case KeyPairAlgorithm.ECDSA:
        if (config.dsaEncoding !== undefined) key.dsaEncoding = config.dsaEncoding
        break
    }

    return {
      factory: () => crypto.createVerify(config.hashAlgorithm),
      key,
    }
  }

  private static createSignContext(config: KeyPairConfig): SignContext | undefined {
    // Bail if no private key present
    if (!config.privateKey) return undefined

    // Check correct key type used
    if (!config.privateKey.asymmetricKeyType || config.privateKey.type !== 'private')
      throw new ConfigurationError(`keypair private key type requires private key, got ${config.publicKey.type}`)

    // Get the equivalent node keypair algorithm for the signature scheme
    const actualSigKeyType = NODE_TO_SIG_KEY_TYPE[config.privateKey.asymmetricKeyType]

    // Reject keys of unknown type
    if (actualSigKeyType === undefined)
      throw new ConfigurationError(
        `keypair private key uses unsupported node crypto key type: ${config.publicKey.asymmetricKeyType}`,
      )
    // Reject keys of differing type to expectation
    if (actualSigKeyType !== config.keyAlgorithm)
      throw new ConfigurationError(
        `expected ${config.keyAlgorithm} private key, but got private key of type ${actualSigKeyType}`,
      )

    // Reject unknown signing hash algorithms
    if (!crypto.getHashes().includes(config.hashAlgorithm))
      throw new ConfigurationError(`keypair hash algorithm not supported: ${config.hashAlgorithm}`)

    // Handle key-type specific config options
    let key: crypto.SignKeyObjectInput = { key: config.privateKey }
    switch (config.keyAlgorithm) {
      case KeyPairAlgorithm.RSA:
        if (config.padding !== undefined) key.padding = config.padding
        if (config.saltLength !== undefined) key.saltLength = config.saltLength
        break
      case KeyPairAlgorithm.ECDSA:
        if (config.dsaEncoding !== undefined) key.dsaEncoding = config.dsaEncoding
        break
    }

    return {
      factory: () => crypto.createSign(config.hashAlgorithm),
      key,
    }
  }

  sign(buf: Buffer): Buffer {
    if (!this.signCtx) throw new ConfigurationError(`cannot sign with public-key only key pairs`)
    const sign = this.signCtx.factory()
    sign.write(buf)
    sign.end()
    return sign.sign(this.signCtx.key)
  }

  verify({ buf, mac }: { buf: Buffer; mac: Buffer }): boolean {
    const verify = this.verifyCtx.factory()
    verify.write(buf)
    verify.end()
    return verify.verify(this.verifyCtx.key, mac)
  }
}
