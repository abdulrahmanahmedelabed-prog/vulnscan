// expect: DF005
import { Controller, Post, UploadedFile, UseInterceptors } from '@nestjs/common';
import * as fs from 'fs';
@Controller('files')
export class FilesController {
  @Post()
  upload(@UploadedFile() file: any) {
    fs.writeFileSync('/srv/uploads/' + file.originalname, file.buffer);
  }
}
