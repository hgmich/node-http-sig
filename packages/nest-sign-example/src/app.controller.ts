import { Controller, Get, Post } from '@nestjs/common'
import { AppService } from './app.service'
import { Signed } from '@holmesmr/nest-http-sig'

@Signed()
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): object {
    return this.appService.getHello()
  }

  @Post()
  getHelloPost(): object {
    return this.appService.getHello()
  }
}
