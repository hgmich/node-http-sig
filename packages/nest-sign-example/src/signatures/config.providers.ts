import { HttpSigVersion, SIGNATURE_CONFIG } from '@holmesmr/nest-http-sig'

export const signatureConfigProvider = {
  provide: SIGNATURE_CONFIG,
  useFactory: () => ({
    version: HttpSigVersion.DRAFT_CAVAGE_12,
  }),
}
