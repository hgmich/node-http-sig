// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import {
  DigestAlgorithm,
  SigningAlgorithm,
  ConfigurationError,
  ConcreteSignatureOptions,
  VerificationError,
  HeaderSignSpec,
  HeaderSignMode,
  SignatureAlgorithm,
  GenericKeyConfigBase,
  SigningKeyConfig,
} from './types'
import * as crypto from 'crypto'
import { MessageContext, HttpMessage } from './MessageContext'

export type DigestFactory = () => crypto.Hash

export type InternalKeyConfig = Omit<GenericKeyConfigBase, 'signatureAlgorithm'> &
  SigningKeyConfig & {
    signatureAlgorithm: SignatureAlgorithm
  }

function headerList(headers: HeaderSignSpec, mode: HeaderSignMode): string[] {
  return Object.entries(headers)
    .filter(([, value]) => value === mode || value === true)
    .map(([header]) => header)
}

/**
 * Encapsulation around various operations specific to a keyId.
 *
 * This includes signing and verifying requests and responses, as well as
 * producing the digest using the configured algorithm.
 *
 * This class is a base abstraction that handles generic functionality to
 * all types of signature; concrete instances are created from subclasses
 * based on the type of key used (symmetric vs. public key).
 *
 * You should not create instances of SignatureKey yourself; instead, they
 * are created through a SignatureKeyManager.
 */
export abstract class SignatureKey {
  protected constructor(
    /** The keyId corresponding to this key */
    readonly id: string,
    /** A factory that creates new crypto.Hash instances for the given digest algorithm */
    private readonly hasher: DigestFactory,
    /** The signature algorithm specified for signatures using this key. */
    readonly signatureAlgorithm: SignatureAlgorithm,
    /** The digest algorithm for signatures using this key. */
    readonly digestAlgorithm: DigestAlgorithm,
    /** The resolved options for signatures using this key. */
    readonly options: ConcreteSignatureOptions,
  ) {}

  /**
   * Create a Digest header for the given Buffer representing the
   * body of an HTTP message.
   *
   * WARNING: **Never** verify the Digest header for an incoming
   * HTTP message by using `==` or `===`. Use the KeyWrapper.verifyDigestHeader
   * method instead. This method should only be used to write the Digest
   * header for a request.
   *
   * @param body Buffer for body to digest according to key config.
   */
  createDigestHeader(body: Buffer): string {
    const digest = this.#digestBuffer(body)

    return `${this.digestAlgorithm}=${digest.toString('base64')}`
  }

  /**
   * Verifies the body of a request against the digest.
   *
   * @throws VerificationError Thrown when algorithm does not match or digest verification failed
   *
   * @param body Buffer containing body of request to be verified
   * @param digest Digest header extracted from request
   */
  verifyDigestHeader(body: Buffer, digest: string): boolean {
    const [cmpAlg, encodedCmpDigest] = digest.split('=', 2)

    if (cmpAlg.toLowerCase() !== this.digestAlgorithm.toLowerCase())
      throw new VerificationError(`mismatched digest algorithm: got ${cmpAlg}, expected ${this.digestAlgorithm}`)

    const cmpDigest = Buffer.from(encodedCmpDigest, 'base64')
    const refDigest = this.#digestBuffer(body)

    if (!crypto.timingSafeEqual(cmpDigest, refDigest)) throw new VerificationError(`body digest verification failed`)

    return true
  }

  /** Identifies the signing algorithm used by this key. Delegated to implementations. */
  abstract get algorithm(): SigningAlgorithm

  /** Signs a Buffer using this key's signing algorithm. May fail if the key is not capable of producing signatures. */
  protected abstract sign(buf: Buffer): Buffer

  /** Verifies a Buffer against an existing signature using this key's signing algorithm. */
  protected abstract verify({ buf, mac }: { buf: Buffer; mac: Buffer }): boolean

  static createDigestFactory(digest: DigestAlgorithm): DigestFactory {
    const digestFactory = (hashName: string) => () => crypto.createHash(hashName)

    if (Object.values(DigestAlgorithm).includes(digest)) {
      switch (digest) {
        case DigestAlgorithm.SHA256:
          return digestFactory('sha256')
        case DigestAlgorithm.SHA512:
          return digestFactory('sha512')
      }
    } else {
      throw new ConfigurationError(`unsupported digest algorithm ${digest}`)
    }
  }

  /**
   * Create a signature string for a given HTTP request.
   *
   * The signature will be signed against the configured headers.
   * If the calculateDigest option is set, the Digest header will
   * be added to the list of signed headers. The header will _not_
   * be automatically added to the request; it must have already
   * been calculated using `SignatureKey.createDigestHeader()`
   * and added to the request before signing.
   *
   * @throws VerificationError if any configured headers are not set on the request
   *
   * @param msgCtx MessageContext wrapper around the HTTP request to be signed.
   */
  signRequest(msgCtx: MessageContext): string {
    return this.#signMessage(msgCtx, this.options.requestHeaders)
  }

  /**
   * Create a signature string for a given HTTP response.
   *
   * The signature will be signed against the configured headers.
   * If the calculateDigest option is set, the Digest header will
   * be added to the list of signed headers. The header will _not_
   * be automatically added to the request; it must have already
   * been calculated using `SignatureKey.createDigestHeader()`
   * and added to the response before signing.
   *
   @throws VerificationError if any configured headers are not set on the response
   *
   * @param msgCtx MessageContext wrapper around the HTTP response to be signed.
   */
  signResponse(msgCtx: MessageContext): string {
    return this.#signMessage(msgCtx, this.options.responseHeaders)
  }

  /**
   * Verify the signature present on a given request.
   *
   * The signature will be verified against the headers specified
   * in the request's signature.
   *
   * @throws VerificationError if the signature is incorrect, is malformed, does not have the
   *                           required headers, or has invalid values for created or expires
   *
   * @param msgCtx MessageContext wrapper around the HTTP request to be verified.
   */
  verifyRequest(msgCtx: MessageContext): boolean {
    return this.#verifyMessage(msgCtx, this.options.requestHeaders)
  }

  verifyResponse(msgCtx: MessageContext): boolean {
    return this.#verifyMessage(msgCtx, this.options.responseHeaders)
  }

  /**
   * Digest a Buffer using the configured digest algorithm, returning a
   * Buffer containing the digest output.
   *
   * @param buf Buffer to produce digest for
   * @private
   */
  #digestBuffer(buf: Buffer): Buffer {
    const hash = this.hasher()
    hash.update(buf)
    return hash.digest()
  }

  #signMessage(msgCtx: MessageContext, headerSpec: HeaderSignSpec): string {
    const headers = headerList(headerSpec, 'sign')
    const algorithm = this.signatureAlgorithm

    if (this.options.calculateDigest && !headers.includes('digest')) headers.push('digest')

    const payload = msgCtx.canonicalString(headers)
    const signature = this.sign(Buffer.from(payload)).toString('base64')

    return `keyId="${this.id}",algorithm="${algorithm}",headers="${headers.join(' ')}",signature="${signature}"`
  }

  #verifyMessage(msgCtx: MessageContext, headerSpec: HeaderSignSpec): boolean {
    const refSig = msgCtx.getSignature()

    if (!refSig) throw new VerificationError('signature not present on message')
    // In the verify case, the headers to check are specified by the signature, not
    // the local config, which is instead used to enforce a minimum set of headers
    // which are signed.
    const headers = refSig.headers

    // Verify that the algorithm matches the expected algorithm for the signature, if provided
    if (refSig.signatureAlgorithm && this.signatureAlgorithm !== refSig.signatureAlgorithm)
      throw new VerificationError(`incorrect signature scheme used for key '${this.id}'`)

    const payload = msgCtx.canonicalString(headers)
    const signatureVerified = this.verify({ buf: Buffer.from(payload, 'utf8'), mac: refSig.signature })

    if (!signatureVerified) throw new VerificationError('signature verification failure')

    // After verifying the signature, we can move onto making assertions about the signature
    const headerSet = new Set(refSig.headers)
    const missingHeaders = headerList(headerSpec, 'verify').filter((header) => !headerSet.has(header))

    if (missingHeaders.length > 0)
      throw new VerificationError(`signature missing required headers: ${missingHeaders.join(', ')}`)

    if (!refSig.validCreation) throw new VerificationError('signature creation in future')
    if (!refSig.validExpires) throw new VerificationError('signature has expired')

    return true
  }
}
