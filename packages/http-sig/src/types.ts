import crypto from 'crypto'

export type KeyConfig = {
  /// The digest algorithm used for producing body digests for requests/responses
  digest: DigestAlgorithm
} & SymmetricKeyConfig

export type SigningAlgorithm = MacAlgorithm

export type SymmetricKeyConfig = {
  /// The MAC algorithm to use to sign/verify requests.
  algorithm: MacAlgorithm
  /// The key to use for the MAC algorithm.
  key: crypto.KeyObject
}

export type MacAlgorithm = HmacAlgorithm

export enum HmacAlgorithm {
  SHA256 = 'hmac-sha256',
  SHA512 = 'hmac-sha512',
}

export enum DigestAlgorithm {
  SHA256 = 'SHA-256',
  SHA512 = 'SHA-512',
}

export type KeyId = string

export type FixedKey = { keyId: KeyId } & KeyConfig
export type KeyLookupFunction = ({ keyId }: { keyId: KeyId }) => KeyConfig
export type KeyLookup = { keyLookup: KeyLookupFunction }

export type KeyLookupParams = FixedKey | KeyLookup

export type RequiredParams = {}

export type OptionalParams = {
  addDate: boolean
  addHost: boolean
}

export type HttpSigParams = KeyLookupParams & RequiredParams & Partial<OptionalParams>

export abstract class SignatureError extends Error {}

export class VerificationError extends SignatureError {}

export class ConfigurationError extends SignatureError {}

export type RequestTarget = {
  method: string
  path: string
}
