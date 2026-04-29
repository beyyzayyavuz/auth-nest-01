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
            const ctx = requestContext.getStore();
            const start = Date.now();
            const result = await query(args);
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

  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}