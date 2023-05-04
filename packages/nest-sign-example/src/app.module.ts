import { Module } from '@nestjs/common'
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core'
import { AppController } from './app.controller'
import { AppService } from './app.service'
import { VerifySignatureGuard, SignResponseInterceptor } from '@holmesmr/nest-http-sig'
import { SignaturesModule } from './signatures/signatures.module'
import { HttpExceptionFilter } from './filters/http-exception.filter'

@Module({
  imports: [SignaturesModule],
  exports: [SignaturesModule],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: VerifySignatureGuard,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: SignResponseInterceptor,
    },
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
  ],
})
export class AppModule {}
