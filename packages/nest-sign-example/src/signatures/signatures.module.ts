import { Module } from '@nestjs/common'
import { signatureProvider } from '@holmesmr/nest-http-sig'
import { SIGNATURE_INST } from '@holmesmr/nest-http-sig'
import { signatureConfigProvider } from './config.providers'
import { keyLookupProvider } from './key-lookup.providers'

@Module({
  providers: [signatureProvider, signatureConfigProvider, keyLookupProvider],
  exports: [SIGNATURE_INST],
})
export class SignaturesModule {}
