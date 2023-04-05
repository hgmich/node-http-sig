import { OptionalParams, KeyLookupFunction, KeyId, VerificationError } from './types'
import { KeyWrapper } from './KeyWrapper'

type RequestSignerParamsInternal = {
  keyLookup: KeyLookupFunction
} & OptionalParams

export class SignatureHandler {
  private keyLookup: KeyLookupFunction

  constructor(config: RequestSignerParamsInternal) {
    this.keyLookup = config.keyLookup
  }

  getKey(keyId: KeyId): KeyWrapper {
    const keyConfig = this.keyLookup({ keyId })

    if (!keyConfig) throw new VerificationError(`Key ${keyId} not found`)

    return KeyWrapper.create(keyConfig)
  }
}
