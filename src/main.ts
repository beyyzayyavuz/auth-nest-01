import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';
import helmet from 'helmet';
import { BackendCostInterceptor } from './common/interceptors/backend-cost.interceptor';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: ['log', 'error', 'warn', 'debug', 'verbose'],
  });

  const logger = new Logger('Bootstrap');

  // CORS — listen'dan önce olmalı
  app.enableCors({
    origin: ['http://localhost:4200'],
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  // Global interceptor
  app.useGlobalInterceptors(new BackendCostInterceptor());

  await app.listen(3000);
  logger.log('Application is running on: http://localhost:3000');
}
bootstrap();