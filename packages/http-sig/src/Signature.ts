// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import { SignatureAlgorithm, VerificationError } from './types'

// TODO: Make configurable
export const EXPIRES_SLACK = 60_000 // 60 seconds
export const CREATED_SLACK = 60_000 // 60 seconds

const MSG_MALFORMED = 'malformed signature string'

const parseStringField = (value: string): string => {
  if (!value.startsWith('"') || !value.endsWith('"')) {
    throw new VerificationError(MSG_MALFORMED)
  }

  // TODO: properly handle nested quotes?
  return value.slice(1, -1)
}

const parseIntField = (value: string): number => {
  if (value.search(/[^0-9]/) !== -1) {
    throw new VerificationError(MSG_MALFORMED)
  }

  // No leading 0
  if (value.startsWith('0') && value !== '0') throw new VerificationError(MSG_MALFORMED)

  return parseInt(value)
}

const parseDecimalField = (value: string): number => {
  if (value.search(/[^0-9.]/) !== -1) {
    throw new VerificationError(MSG_MALFORMED)
  }

  // Additional strictness checks to compensate for slackness of parseFloat
  const firstDecimalIdx = value.indexOf('.')
  const lastDecimalIdx = value.lastIndexOf('.')
  // No leading/trailing decimals
  if (firstDecimalIdx === 0 || lastDecimalIdx === value.length - 1) throw new VerificationError(MSG_MALFORMED)
  // No leading 0 in numerator (sometimes ambiguous about decimal or octal notation)
  // If value.length > 1, and there's an initial 0, then the only permitted following char is '.'
  if (value.startsWith('0') && value.length > 1 && firstDecimalIdx !== 1) throw new VerificationError(MSG_MALFORMED)
  // maximum of 1 decimal separator
  // this works for 0 or 1 because firstDecimalIdx and lastDecimalIdx are -1 when decimal separator missing
  if (firstDecimalIdx !== lastDecimalIdx) throw new VerificationError(MSG_MALFORMED)

  return parseFloat(value)
}

const pairsToMap = (pairs: string[]): Map<string, string> => {
  const out = new Map()

  pairs.forEach((pair) => {
    const eqLocation = pair.indexOf('=')
    if (eqLocation < 0) throw new VerificationError('malformed signature string (missing `=` in field)')
    const key = pair.slice(0, eqLocation)
    const value = pair.slice(eqLocation + 1)

    if (!key || !value || key.search(/\s/) !== -1) {
      throw new VerificationError(MSG_MALFORMED)
    }

    if (out.has(key)) throw new VerificationError(`duplicated field ${key} present in signature`)

    out.set(key, value)
  })

  return out
}

const getKeyId = (fieldMap: Map<string, string>): string => {
  const keyId = fieldMap.get('keyId')

  if (!keyId) throw new VerificationError('required field `keyId` not present in signature')

  return parseStringField(keyId)
}

const getSignatureAlgorithm = (fieldMap: Map<string, string>): SignatureAlgorithm | undefined => {
  const algorithmVal = fieldMap.get('algorithm')

  if (!algorithmVal) return undefined
  const algorithm = parseStringField(algorithmVal)

  // string->string enums cannot be inverse lookup'd in a way provable to the compiler
  if (!Object.values(SignatureAlgorithm).includes(algorithm as SignatureAlgorithm))
    throw new VerificationError(`signature algorithm \`${algorithm}\` is not supported`)

  return algorithm as SignatureAlgorithm
}

const DEFAULT_HEADERS = Object.freeze(['(created)'])

const getHeaders = (fieldMap: Map<string, string>): string[] => {
  const headersStr = fieldMap.get('headers')

  if (!headersStr) return [...DEFAULT_HEADERS]

  const headers = parseStringField(headersStr)
    .split(' ')
    .map((header) => header.toLowerCase())

  // TODO: improved validation of headers around inclusion of ','
  if (headers.some((s) => s.length === 0 || s.search(/\s/) !== -1))
    throw new VerificationError('malformed header list in signature string')

  return headers
}

const getSignature = (fieldMap: Map<string, string>): Buffer => {
  const signatureStrVal = fieldMap.get('signature')

  if (!signatureStrVal) throw new VerificationError('required field `signature` not present in signature')
  const signatureStr = parseStringField(signatureStrVal)

  const signature = Buffer.from(signatureStr, 'base64')

  const unpaddedSignatureString = signatureStr.replace(/=/g, '')
  // Check for malformed base64 strings
  if (Math.floor(unpaddedSignatureString.length * (3 / 4)) !== signature.length || signature.length === 0) {
    throw new VerificationError('invalid base64 string provided in signature')
  }

  return signature
}

const getCreated = (fieldMap: Map<string, string>): Date | undefined => {
  const createdStr = fieldMap.get('created')

  if (!createdStr) return undefined

  // Fractional second precision is not allowed in the created field
  const createdNum = parseIntField(createdStr)

  return new Date(Math.floor(createdNum * 1000))
}

const getExpires = (fieldMap: Map<string, string>): Date | undefined => {
  const expiresStr = fieldMap.get('expires')

  if (!expiresStr) return undefined

  // Fractional second precision is allowed in the expires field
  const expiresNum = parseDecimalField(expiresStr)

  return new Date(Math.floor(expiresNum * 1000))
}

export class Signature {
  readonly observedAt: Date

  protected constructor(
    readonly keyId: string,
    readonly signature: Buffer,
    readonly headers: string[],
    readonly signatureAlgorithm?: SignatureAlgorithm,
    readonly created?: Date,
    readonly expires?: Date,
    observedAt?: Date,
  ) {
    this.observedAt = observedAt || new Date()
  }

  static fromHeader(header: string, atTime?: Date): Signature {
    const pairs = header.split(',')
    const fieldMap = pairsToMap(pairs)

    // Required fields and defaulted fields
    const keyId = getKeyId(fieldMap)
    const signature = getSignature(fieldMap)
    const headers = getHeaders(fieldMap)

    // Optional fields
    const signatureAlgorithm = getSignatureAlgorithm(fieldMap)
    const created = getCreated(fieldMap)
    const updated = getExpires(fieldMap)

    return new Signature(keyId, signature, headers, signatureAlgorithm, created, updated, atTime)
  }

  get signedCreated(): boolean {
    return this.created !== undefined && this.headers.includes('(created)')
  }

  get signedExpires(): boolean {
    return this.expires !== undefined && this.headers.includes('(expires)')
  }

  get validCreation(): boolean {
    if (this.created === undefined) return true
    // created - observedAt = number of msec in future creation is from now
    // negative: in past
    // Slack: can be no further in future than CREATED_SLACK
    return this.created.valueOf() - this.observedAt.valueOf() < CREATED_SLACK
  }

  get validExpires(): boolean {
    if (this.expires === undefined) return true
    // observedAt - expires = seconds since expiry
    // negative: not expired
    // Slack: can be no more than CREATED_SLACK since expiry
    return this.observedAt.valueOf() - this.expires.valueOf() < EXPIRES_SLACK
  }
}
