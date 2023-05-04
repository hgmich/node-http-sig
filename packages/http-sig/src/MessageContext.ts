// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import { VerificationError, ConfigurationError } from './types'
import { Signature } from './Signature'

export type NonEmptyArray<T> = Exclude<T[], []>

/**
 * An abstraction around library-specific objects for HTTP messages.
 *
 * Your library creates objects conforming to this interface to allow http-sig to get the
 * necessary information from HTTP requests and responses to produce and verify
 * signatures.
 */
export interface HttpMessage {
  getHeader(header: string): NonEmptyArray<string> | undefined
  requestTarget?: { method: string; path: string }
}

type MessageContextOptions = {
  createdAt?: string
  expiresAt?: string
}

/**
 * Wrapper class around HTTP messages to help with signing.
 *
 * The primary use of `MessageContext` is to build a correct canonical string for the
 * headers in an abstract way. You do not need to implement or interact with
 * `MessageContext` directly except to create instances
 * through the `createMessageContext` function.
 */
export class MessageContext {
  private options: MessageContextOptions

  /**
   * Creates a new `MessageContext` instance, which allows for abstracted operations on
   * an HTTP message (request/response).
   *
   * You must not use this method to directly create instances of `MessageContext`;
   * it is only intended for internal use by the http-sig library. Instances should
   * be retrieved through a `SignatureKey` implementation.
   *
   * @param message The underlying `HttpMessage` used to interact with the HTTP message to be signed
   *                or verified
   * @param options Options relating to pseudo-headers such as `(created)` and `(expires)`.
   *
   * @private
   */
  constructor(private message: HttpMessage, options?: MessageContextOptions) {
    this.options = options || {}
  }

  private getHeader(name: string): string[] | undefined {
    const normalizedName = name.toLowerCase()

    let headerValues
    switch (normalizedName) {
      case '(request-target)':
        headerValues = [this.getRequestTarget()]
        break
      case '(created)':
        headerValues = this.options.createdAt ? [this.options.createdAt] : undefined
        break
      case '(expires)':
        headerValues = this.options.expiresAt ? [this.options.expiresAt] : undefined
        break
      default:
        headerValues = this.message.getHeader(normalizedName)
    }

    return headerValues
  }

  private getRequestTarget(): string {
    if (!this.message.requestTarget)
      throw new ConfigurationError('BUG: attempted to sign/verify (request-target) for response')

    const { method, path } = this.message.requestTarget
    return `${method.toLowerCase()} ${path}`
  }

  /**
   * Build the canonical string for an HTTP message.
   *
   * The canonical string is used to generate the payload for the signature.
   * Note that the order of the headers matters, as specified below.
   *
   * @param headers Array of header names used to build the canonical string.
   *                The headers are ordering-sensitive; using the same headers
   *                in a different order will result in a different signature.
   *
   * @throws VerificationError if an entry in `headers` is not found on the message
   */
  canonicalString(headers: string[]): string {
    const mergedHeaders = headers.map((h) => {
      const lowerName = h.toLowerCase()
      const headerValues = this.getHeader(lowerName)

      if (headerValues === undefined) throw new VerificationError(`attempted to sign/verify missing header '${h}'`)

      // Header must not have trailing whitespace if empty
      return `${lowerName}: ${headerValues.join(', ')}`.trimEnd()
    })

    return mergedHeaders.join('\n')
  }

  /**
   * Get a structured Signature from an HTTP message.
   *
   * If no signature is present in the Authorization or Signature headers,
   * then the function returns `undefined`.
   *
   * If multiple candidate signatures are present, an exception is raised.
   * Note that this behaviour is not specified in the IETF spec; this is
   * the http-sig library's own interpretation.
   */
  getSignature(atTime?: Date): Signature | undefined {
    // Signatures can be present in either the Signature header or as part of the
    // Authorization: Signature scheme
    const signatureHeaders = this.getHeader('signature')
    const signatureAuthHeaders = this.getHeader('authorization')
      ?.filter((auth) => auth.startsWith('Signature '))
      .map((auth) => {
        const spaceIdx = auth.indexOf(' ')
        return auth.slice(spaceIdx + 1)
      })
    const signatures = [...(signatureHeaders || []), ...(signatureAuthHeaders || [])]

    // Bail if no signatures
    if (signatures.length < 1) return undefined

    // Throw error if multiple signatures
    // TODO: the behaviour in the presence of multiple signatures is not defined in draft-cavage-http-signatures-12
    if (signatures.length > 1) throw new VerificationError('multiple signatures present on message')

    return Signature.fromHeader(signatures[0], atTime)
  }
}
