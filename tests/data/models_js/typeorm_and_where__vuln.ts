// expect: DF004
import { Controller, Get, Query } from '@nestjs/common';
@Controller('users')
export class UsersController {
  constructor(private readonly repo: any) {}
  @Get()
  find(@Query('role') role: string) {
    return this.repo.createQueryBuilder('u').where('u.active = true').andWhere(`u.role = '${role}'`).getMany();
  }
}
