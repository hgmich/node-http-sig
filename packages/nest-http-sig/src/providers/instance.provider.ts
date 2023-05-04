// Copyright (c) Michael Holmes
// SPDX-License-Identifier: MIT

import { KeyLookupParams, VersionParams, SignatureKeyManager, signatures } from '@holmesmr/http-sig'

import { SIGNATURE_CONFIG, SIGNATURE_INST, SIGNATURE_KEY_LOOKUP } from '../constants'

export const signatureProvider = {
  provide: SIGNATURE_INST,
  useFactory: (config: VersionParams, keyLookup: KeyLookupParams): SignatureKeyManager =>
    signatures({
      ...config,
      ...keyLookup,
    }),
  inject: [SIGNATURE_CONFIG, SIGNATURE_KEY_LOOKUP],
}
