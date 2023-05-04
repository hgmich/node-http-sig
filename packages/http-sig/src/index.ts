// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import { SignatureKeyManager } from './SignatureKeyManager'
import { HttpMessage, MessageContext } from './MessageContext'

import { HttpSigParams } from './types'

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

/**
 * Create a new MessageContext for handing signing or verifying
 * a given HTTP message.
 *
 * @param message A HttpMessage instance wrapping an underlying
 *                HTTP message from a library.
 */
export function createMessageContext(message: HttpMessage): MessageContext {
  return new MessageContext(message)
}

export default signatures

export { SignatureKey } from './SignatureKey'
export { HttpMessage, MessageContext } from './MessageContext'
export { Signature } from './Signature'
export { SignatureKeyManager } from './SignatureKeyManager'
export * from './types'
