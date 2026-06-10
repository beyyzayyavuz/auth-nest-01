import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { requestContext } from '../common/request-context/request-context';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  constructor() {
    super();

    // $extends ile query timing — AsyncLocalStorage context'i koruyor
    return this.$extends({
      query: {
        $allModels: {
          async $allOperations({ operation, model, args, query }) {
            const ctx = requestContext.getStore(); // AsyncLocalStorage'dan mevcut request'in metrics objesini al. Yani aslında o anki isteğin izole kasasına bakar.
            const start = Date.now(); // Kronometre başlat
            const result = await query(args); // Asıl Prisma query'sini çalıştır ve sorguyu veritabanına gönder.
            const duration = Date.now() - start;
            if (ctx) {
              ctx.dbQueryCount += 1;
              ctx.dbTotalTimeMs += duration;
            }
            return result;
          },
        },
      },
    }) as PrismaService;
  }

  // Postgres veritabanına giden fiziksel bağlantı köprüsünü kurar. Sunucu açılır açılmaz veritabanına hazır hale gelir.
  async onModuleInit() {
    await this.$connect();
  }

  // Veritabanı bağlantısını temizler. Sunucu kapanırken veritabanı bağlantısını düzgün şekilde kapatır. leak'ler kalmaz böylece.
  async onModuleDestroy() {
    await this.$disconnect();
  }
}