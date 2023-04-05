import { SignatureHandler } from './SignatureHandler'

import {
  HttpSigParams,
  OptionalParams,
  KeyLookupFunction,
  FixedKey,
  KeyLookup,
  KeyConfig,
  KeyId,
  ConfigurationError,
} from './types'

const DEFAULT_OPTS: OptionalParams = {
  addDate: true,
  addHost: true,
}

function fixedKeyLookup(fixedKeyId: KeyId, keyConfig: KeyConfig): KeyLookupFunction {
  return ({ keyId }: { keyId: string }) => {
    if (keyId !== fixedKeyId) throw new Error(`Unknown key ${keyId}`)

    return keyConfig
  }
}

export function createSignatureHandler(config: HttpSigParams): SignatureHandler {
  const fixedKeyVariant = config as FixedKey
  const keyLookupVariant = config as KeyLookup

  let modifiedConfig: KeyLookup
  if (fixedKeyVariant.keyId) {
    const keyLookup = fixedKeyLookup(fixedKeyVariant.keyId, fixedKeyVariant)
    let { key, keyId, digest, algorithm, ...strippedConfig } = fixedKeyVariant
    modifiedConfig = { ...strippedConfig, keyLookup }
  } else if (keyLookupVariant.keyLookup) {
    modifiedConfig = { ...config, keyLookup: keyLookupVariant.keyLookup }
  } else {
    throw new ConfigurationError('Either a fixed {keyId, key} or a key lookup function must be provided')
  }

  if (!modifiedConfig?.keyLookup)
    throw new ConfigurationError('Either a fixed {keyId, key} or a key lookup function must be provided')

  const finalConfig = { ...DEFAULT_OPTS, ...modifiedConfig }

  return new SignatureHandler(finalConfig)
}

export default createSignatureHandler

export { KeyWrapper } from './KeyWrapper'
export * from './types'
