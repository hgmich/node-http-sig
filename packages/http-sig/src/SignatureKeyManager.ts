// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import {
  ConcreteSignatureOptions,
  ConfigurationError,
  DigestAlgorithm,
  FixedKey,
  HmacAlgorithm,
  HttpSigParams,
  HttpSigVersion,
  KeyConfig,
  KeyId,
  KeyLookup,
  KeyLookupFunction,
  KeyPairConfig,
  RequiredSignatureOptions,
  SecretKeyConfig,
  SignatureAlgorithm,
  SignatureOptionOverrides,
  SignatureOptions,
  VerificationError,
} from './types'
import { InternalKeyConfig, SignatureKey } from './SignatureKey'
import { HmacSignatureKey } from './HmacSignatureKey'
import { HttpMessage, MessageContext } from './MessageContext'

type ResolvedOptions = RequiredSignatureOptions & Required<SignatureOptions>

type RequestSignerParamsInternal = {
  keyLookup: KeyLookupFunction
} & ResolvedOptions

function firstDefined<T>(vals: (T | undefined)[]): T | undefined {
  for (const val of vals) {
    if (val !== undefined) return val
  }

  return undefined
}

function hasKey<O extends object>(obj: O, key: PropertyKey): key is keyof O {
  return key in obj
}

function fixedKeyLookup(fixedKeyId: KeyId, keyConfig: KeyConfig): KeyLookupFunction {
  return ({ keyId }: { keyId: string }) => {
    if (keyId !== fixedKeyId) return undefined

    return keyConfig
  }
}

const DEFAULT_OPTS: Required<SignatureOptions> = Object.freeze({
  signatureAlgorithm: SignatureAlgorithm.HS2019,
  requestHeaders: Object.freeze({ '(request-target)': true, host: true }),
  responseHeaders: Object.freeze({}),
  calculateDigest: true,
})

export class SignatureKeyManager {
  private readonly keyLookup: KeyLookupFunction
  private baseSigningOptions: ResolvedOptions

  private constructor({ keyLookup, ...baseSigningConfig }: RequestSignerParamsInternal) {
    this.keyLookup = keyLookup
    this.baseSigningOptions = baseSigningConfig
  }

  private getKeySigningOptions(keyId: string, overrides: SignatureOptionOverrides): ResolvedOptions {
    const resolvedOptions = Object.fromEntries(
      Object.entries(this.baseSigningOptions).map(([optionKey, value]) => {
        if (!hasKey(overrides, optionKey)) return [optionKey, value]
        const effectiveValue = firstDefined([overrides[optionKey], value])

        if (effectiveValue === undefined)
          throw new ConfigurationError(`key config for ${keyId} has unset option ${optionKey}`)

        return [optionKey, effectiveValue]
      }),
    ) as ResolvedOptions // above checks will ensure that resolvedOptions has all options set to definite values

    return resolvedOptions
  }

  /** Get the corresponding SignatureKey for a keyId, throwing a VerificationError
   * if the specified keyId was not found.
   *
   * @throws VerificationError if the specified keyId was not found
   * @throws ConfigurationError if the corresponding key has invalid configuration
   */
  async tryGetKey(keyId: KeyId): Promise<SignatureKey | undefined> {
    let keyConfig = await this.keyLookup({ keyId })

    if (!keyConfig) return undefined

    const options = this.getKeySigningOptions(keyId, keyConfig)
    const secretKeyConfig = keyConfig as SecretKeyConfig

    let finalKeyConfig: InternalKeyConfig

    // Override key config with fixed algorithm options when not using HS2019
    if (keyConfig.signatureAlgorithm != SignatureAlgorithm.HS2019) {
      switch (keyConfig.signatureAlgorithm) {
        case SignatureAlgorithm.HMAC_SHA256: {
          if (!secretKeyConfig.algorithm) throw new ConfigurationError(`cannot use hmac-sha256 with public keys`)
          finalKeyConfig = {
            ...keyConfig,
            digest: DigestAlgorithm.SHA256,
            algorithm: HmacAlgorithm.SHA256,
          } as InternalKeyConfig
          break
        }
        // TODO: include rsa-sha256 and ecdsa-sha256
        default:
          throw new ConfigurationError(
            `unrecognized signature algorithm requested for key '${keyId}': ${(keyConfig as any).signatureAlgorithm}`,
          )
      }
    } else {
      finalKeyConfig = keyConfig
    }

    return SignatureKeyManager.#createSignatureKey(keyId, finalKeyConfig, options)
  }

  /** Get the corresponding SignatureKey for a keyId, throwing a VerificationError
   * if the specified keyId was not found.
   *
   * @throws VerificationError if the specified keyId was not found
   * @throws ConfigurationError if the corresponding key has invalid configuration
   */
  async getKey(keyId: KeyId): Promise<SignatureKey> {
    const key = await this.tryGetKey(keyId)

    if (!key) throw new VerificationError(`key ${keyId} not found`)

    return key
  }

  /**
   * Create a new instance of the `SignatureKeyManager` from the given `config`.
   *
   * This is only intended to be used by the public `signatures` function of
   * this package. Its API may change without warning.
   *
   * @param config Configuration options provided by the user
   *
   * @private
   */
  static create(config: HttpSigParams): SignatureKeyManager {
    // Cast to variants is easier to handle
    const fixedKeyVariant = config as FixedKey & { digest?: DigestAlgorithm }
    const keyLookupVariant = config as KeyLookup

    if (config.version !== HttpSigVersion.DRAFT_CAVAGE_12)
      throw new ConfigurationError(`unsupported signature version ${config.version}`)

    let modifiedConfig
    if (fixedKeyVariant.keyId) {
      const keyLookup = fixedKeyLookup(fixedKeyVariant.keyId, fixedKeyVariant)

      let { keyId, digest, ...baseStrippedConfig } = fixedKeyVariant
      const secretKeyConfig = baseStrippedConfig as SecretKeyConfig
      const keyPairConfig = baseStrippedConfig as KeyPairConfig

      let strippedConfig
      if (secretKeyConfig.algorithm) {
        let { algorithm, key, ...newStrippedConfig } = secretKeyConfig
        strippedConfig = newStrippedConfig
      } else if (keyPairConfig.keyAlgorithm) {
        let { keyAlgorithm, hashAlgorithm, publicKey, privateKey, ...newStrippedConfig } = keyPairConfig
        strippedConfig = newStrippedConfig
      } else {
        throw new ConfigurationError('unrecognized fixed key configuration')
      }

      modifiedConfig = { ...strippedConfig, keyLookup }
    } else if (keyLookupVariant.keyLookup) {
      modifiedConfig = { ...config, keyLookup: keyLookupVariant.keyLookup }
    } else {
      throw new ConfigurationError('either a fixed {keyId, key} or a key lookup function must be provided')
    }

    if (!modifiedConfig?.keyLookup)
      throw new ConfigurationError('either a fixed {keyId, key} or a key lookup function must be provided')

    const finalConfig = { ...DEFAULT_OPTS, ...modifiedConfig }

    return new SignatureKeyManager(finalConfig)
  }

  // Ideally this would live on SignatureKey, but that introduces a
  // circular reference between SignatureKey and HmacSignatureKey.
  static #createSignatureKey(id: string, config: InternalKeyConfig, options: ConcreteSignatureOptions): SignatureKey {
    const hasher = SignatureKey.createDigestFactory(config.digest)

    const secretKeyConfig = config as SecretKeyConfig
    const keyPairConfig = config as KeyPairConfig

    if (secretKeyConfig.algorithm) {
      if (Object.values(HmacAlgorithm).includes(secretKeyConfig.algorithm)) {
        return new HmacSignatureKey(id, config.signatureAlgorithm, hasher, config.digest, secretKeyConfig, options)
      }

      throw new ConfigurationError(`unsupported signing algorithm ${secretKeyConfig.algorithm}`)
    } else if (keyPairConfig.keyAlgorithm) {
      // TODO: allow constructing keyPairConfig objects
      throw new ConfigurationError('key pair algorithms are not yet supported')
    } else {
      throw new ConfigurationError('got unrecognized key configuration object')
    }
  }
}
