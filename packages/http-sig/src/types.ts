// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import * as crypto from 'crypto'

export type SignatureOptionOverrides = Partial<RequiredSignatureOptions> & SignatureOptions
export type ConcreteSignatureOptions = Required<SignatureOptionOverrides>

export type KeyConfig = GenericKeyConfig | LegacyHmacSha256Config

export type GenericKeyConfig = GenericKeyConfigBase & SigningKeyConfig

export type GenericKeyConfigBase = {
  // Generic key config requires HMAC
  signatureAlgorithm: SignatureAlgorithm.HS2019
  /// The digest algorithm used for producing body digests for requests/responses
  digest: DigestAlgorithm
  /// Per-key optional overrides to signing options
  options?: SignatureOptionOverrides
}

export type LegacyHmacSha256Config = {
  // Generic key config requires HMAC
  signatureAlgorithm: SignatureAlgorithm.HMAC_SHA256
  /// Per-key optional overrides to signing options
  options?: SignatureOptionOverrides
} & SecretKeyConfig

export type SigningKeyConfig = SecretKeyConfig | KeyPairConfig

export type SigningAlgorithm = MacAlgorithm | KeyPairAlgorithm

export type SecretKeyConfig = {
  /// The MAC algorithm to use to sign/verify requests.
  algorithm: MacAlgorithm
  /// The key to use for the MAC algorithm.
  key: crypto.KeyObject
}

export type BaseKeyPairConfig = {
  /// The digital signature hash algorithm to use to sign/verify requests.
  /// examples: SHA-256, SHA-512
  hashAlgorithm: string
  /// The digital signature keypair algorithm for the keys.
  keyAlgorithm: KeyPairAlgorithm
  /// A key that is able to verify signatures, but not create them.
  publicKey: crypto.KeyObject
  /// A key that is able to create signatures but not verify them, although the
  /// corresponding public key can usually be generated from the private key.
  privateKey?: crypto.KeyObject
}

export type RsaKeyPairConfig = BaseKeyPairConfig & {
  /// The digital signature keypair algorithm for the keys.
  keyAlgorithm: KeyPairAlgorithm.RSA

  /// The padding scheme to use for signatures.
  padding?: RsaPaddingScheme

  /// The salt length to use for RSA signatures.
  saltLength?: number
}

export type DsaKeyPairConfig = BaseKeyPairConfig & {
  /// The digital signature keypair algorithm for the keys.
  keyAlgorithm: KeyPairAlgorithm.ECDSA

  /// Which of the DSA signature format encodings is used.
  dsaEncoding?: DsaEncodingType
}

export type KeyPairConfig = RsaKeyPairConfig | DsaKeyPairConfig

/// MAC algorithms can be symmetric cipher MACs or Hash-based MACs (HMAC).
/// Only HMAC is supported currently.
export type MacAlgorithm = HmacAlgorithm

/// Digital signature algorithms use a hash function in concert with a
/// digital signature scheme.
export enum KeyPairAlgorithm {
  RSA = 'rsa',
  ECDSA = 'ecdsa',
}

export enum HmacAlgorithm {
  SHA256 = 'hmac-sha256',
  SHA512 = 'hmac-sha512',
}

export enum DigestAlgorithm {
  SHA256 = 'SHA-256',
  SHA512 = 'SHA-512',
}

export enum DsaEncodingType {
  DER = 'der',
  IEEE_P1363 = 'ieee-p1363',
}

export enum RsaPaddingScheme {
  PKCS1 = crypto.constants.RSA_PKCS1_PADDING,
  PKCS1_PSS = crypto.constants.RSA_PKCS1_PSS_PADDING,
}

export type KeyId = string

export type FixedKey = { keyId: KeyId } & KeyConfig
export type KeyLookupFunction = ({ keyId }: { keyId: KeyId }) => KeyConfig | Promise<KeyConfig | undefined> | undefined
export type KeyLookup = { keyLookup: KeyLookupFunction }

export type KeyLookupParams = FixedKey | KeyLookup

export enum HttpSigVersion {
  DRAFT_CAVAGE_12 = 'draft-cavage-http-signatures-12',
}

export type VersionParams = {
  version: HttpSigVersion
}

export type HeaderSignMode = 'sign' | 'verify'
export type HeaderSignSpec = {
  [k in string]: HeaderSignMode | true
}

export type RequiredSignatureOptions = {}

export enum SignatureAlgorithm {
  /// Recommended: no inferences made about key type.
  HS2019 = 'hs2019',

  /// rsa-sha256 signature scheme, AKA:
  /// * Public key algorithm: RSA
  /// * Signature digest algorithm: SHA256
  /// * Padding scheme: PKCS1-V1.5
  ///
  /// Deprecated: control over signature scheme is an attack vector which
  /// reduces security of signatures
  RSA_SHA256 = 'rsa-sha256',

  /// hmac-sha256 signature scheme, AKA:
  /// * Signature scheme: HMAC
  /// * Signature digest algorithm: SHA256
  ///
  /// Deprecated: control over signature scheme is an attack vector which
  /// reduces security of signatures
  HMAC_SHA256 = 'hmac-sha256',

  /// ecdsa-sha256 signature scheme, AKA:
  /// * Public key algorithm: ECDSA
  /// * Signature digest algorithm: SHA256
  /// * Signature format: DER (assumed)
  /// * ECDSA Curve: P-256
  ///
  /// Deprecated: control over signature scheme is an attack vector which
  /// reduces security of signatures
  ECDSA_SHA256 = 'ecdsa-sha256',
}

export type SignatureOptions = Partial<{
  requestHeaders: HeaderSignSpec
  responseHeaders: HeaderSignSpec
  calculateDigest: boolean
}>

export type HttpSigParams = VersionParams & KeyLookupParams & RequiredSignatureOptions & SignatureOptions

export abstract class SignatureError extends Error {
  get name(): string {
    return 'SignatureError'
  }
}

export class VerificationError extends SignatureError {
  get name(): string {
    return 'VerificationError'
  }
}

export class ConfigurationError extends SignatureError {
  get name(): string {
    return 'ConfigurationError'
  }
}

export type RequestTarget = {
  method: string
  path: string
}
