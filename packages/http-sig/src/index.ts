// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import { SignatureKeyManager } from './SignatureKeyManager'

import {
  ConfigurationError,
  FixedKey,
  HttpSigParams,
  HttpSigVersion,
  KeyConfig,
  KeyId,
  KeyLookup,
  KeyLookupFunction,
  SignatureAlgorithm,
  SignatureOptions,
} from './types'

/**
 * Creates a new `SignatureKeyManager` instance using the provided
 * config.
 *
 * This is the only supported way to create new `SignatureKeyManager`
 * instances; constructing new `SignatureKeyManager` instances directly
 * or using `SignatureKeyManager.create()` is not supported and breaking
 * changes may be made without warning.
 *
 * @param config The configuration to use for signing messages
 */
export function signatures(config: HttpSigParams): SignatureKeyManager {
  return SignatureKeyManager.create(config)
}

export default signatures

export { SignatureKey } from './SignatureKey'
export { HttpMessage, MessageContext } from './MessageContext'
export { Signature } from './Signature'
export { SignatureKeyManager } from './SignatureKeyManager'
export * from './types'
