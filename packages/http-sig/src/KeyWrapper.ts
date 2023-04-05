import {
  KeyConfig,
  HmacAlgorithm,
  DigestAlgorithm,
  SigningAlgorithm,
  ConfigurationError,
  SymmetricKeyConfig,
} from './types'
import * as crypto from 'crypto'

type HmacFactory = () => crypto.Hmac
export type DigestFactory = () => crypto.Hash

export abstract class KeyWrapper {
  private _digestAlgorithm: DigestAlgorithm
  private hasher: DigestFactory

  constructor(hasher: DigestFactory, algorithm: DigestAlgorithm) {
    this.hasher = hasher
    this._digestAlgorithm = algorithm
  }

  digest(buf: Buffer): Buffer {
    const hash = this.hasher()
    hash.update(buf)
    return hash.digest()
  }

  get digestAlgorithm() {
    return this._digestAlgorithm
  }

  abstract get algorithm(): SigningAlgorithm

  protected abstract sign(buf: Buffer): Buffer

  protected abstract verify({ buf, mac }: { buf: Buffer; mac: Buffer }): boolean

  private static createDigestFactory(digest: DigestAlgorithm): DigestFactory {
    const digestFactory = (hashName: string) => () => crypto.createHash(hashName)
    console.log(digest, Object.values(DigestAlgorithm))
    if (Object.values(DigestAlgorithm).includes(digest)) {
      switch (digest) {
        case DigestAlgorithm.SHA256:
          return digestFactory('sha256')
        case DigestAlgorithm.SHA512:
          return digestFactory('sha512')
      }
    } else {
      throw new ConfigurationError(`Unsupported digest algorithm ${digest}`)
    }
  }

  static create(config: KeyConfig): KeyWrapper {
    const hasher = KeyWrapper.createDigestFactory(config.digest)

    if (Object.values(HmacAlgorithm).includes(config.algorithm)) {
      return new HmacKeyWrapper(hasher, config.digest, config)
    } else {
      throw new ConfigurationError(`Unsupported signing algorithm ${config.algorithm}`)
    }
  }
}

export class HmacKeyWrapper extends KeyWrapper {
  private hmac: HmacFactory
  private _algorithm: HmacAlgorithm

  get algorithm() {
    return this._algorithm
  }

  constructor(hasher: DigestFactory, digest: DigestAlgorithm, config: SymmetricKeyConfig) {
    super(hasher, digest)
    this.hmac = HmacKeyWrapper.createHmacFactory(config)
    this._algorithm = config.algorithm
  }

  static createHmacFactory(config: SymmetricKeyConfig) {
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

    return crypto.timingSafeEqual(actualMac, mac)
  }
}
