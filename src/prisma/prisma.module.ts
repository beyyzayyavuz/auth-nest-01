import { Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

@Module({
  providers: [PrismaService],
  exports: [PrismaService], // DIŞA AKTARMA YAPILDI DİĞER MODÜLLER GÖREBİLSİN DİYE. Have been receiving errors by now due to the lack of this "exports". Try on, let it happen.
})
export class PrismaModule {}
