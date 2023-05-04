import * as crypto from 'crypto'

import {
  DigestAlgorithm,
  HmacAlgorithm,
  KeyLookupParams,
  SIGNATURE_KEY_LOOKUP,
  SignatureAlgorithm,
} from '@holmesmr/nest-http-sig'

const createSymmetricKey = ({ value, encoding }: { value: string; encoding: 'hex' | 'base64' }) =>
  crypto.createSecretKey(Buffer.from(value, encoding))

export const keyLookupProvider = {
  provide: SIGNATURE_KEY_LOOKUP,
  useFactory: (): KeyLookupParams => {
    return {
      keyLookup: ({ keyId: string }) => ({
        signatureAlgorithm: SignatureAlgorithm.HS2019,
        digest: DigestAlgorithm.SHA256,
        algorithm: HmacAlgorithm.SHA256,
        key: createSymmetricKey({
          encoding: 'base64',
          value: 'SPJp2BUqwI0bFSe/+mh3vKq5yk0eVOG+2fsIqgcgo7s=',
        }),
      }),
    }
  },
}
