import { Body, Controller, Delete, Get, Headers, Param, Post, Query, UseGuards } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { Cron } from '@nestjs/schedule';
import { AuthGuard } from '@nestjs/passport';
import { exec } from 'child_process';
import { CreateCatDto } from './create-cat.dto';
import { Public } from './public.decorator';

@Controller('cats')
@UseGuards(AuthGuard('jwt'))
export class CatsController {
  constructor(private readonly catsService: CatsService) {}

  @Public()
  @Get()
  findAll(@Query('breed') breed: string, @Headers('x-tenant') tenant: string) {
    return this.catsService.findAll(breed, tenant);
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.catsService.findOne(id);
  }

  @Post()
  create(@Body() dto: CreateCatDto) {
    return this.catsService.create(dto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    exec('rm -rf /data/cats/' + id);
    return { removed: id };
  }

  @MessagePattern('cats.created')
  onCreated(@Payload() data: any) {
    return data;
  }

  @Cron('0 3 * * *')
  cleanup() {
    return true;
  }
}
