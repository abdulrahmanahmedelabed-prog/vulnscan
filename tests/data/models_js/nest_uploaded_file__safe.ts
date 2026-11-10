// expect-none: DF005
import { Controller, Post, UploadedFile, UseInterceptors } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
@Controller('files')
export class FilesController {
  @Post()
  upload(@UploadedFile() file: any) {
    fs.writeFileSync('/srv/uploads/' + path.basename(file.originalname), file.buffer);
  }
}
