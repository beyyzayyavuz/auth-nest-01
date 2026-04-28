import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { RequestLoggerMiddleware } from './middleware/request-logger.middleware';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { PrismaModule } from './prisma/prisma.module';
import { LogsModule } from './logs/logs.module';
import { AppController } from './app.controller';     // ← ekle
import { AppService } from './app.service';           // ← ekle
import { MetricsModule } from './metrics/metrics.module';


@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }), // global
    LogsModule,
    AuthModule,
    UserModule,
    PrismaModule,
    MetricsModule,   // ← ekle
  ],
  controllers: [AppController],   // ← ekle
  providers: [AppService],        // ← ekle
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(RequestLoggerMiddleware)
      .forRoutes('*');
    
  }
}