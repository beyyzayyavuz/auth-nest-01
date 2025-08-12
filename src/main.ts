import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: ['log', 'error', 'warn', 'debug', 'verbose'],
  });

  const logger = new Logger('Bootstrap');
  logger.log('Application is starting...');

  await app.listen(3000);
  logger.log('Application is running on: http://localhost:3000');
  app.enableCors({
    origin: ['http://localhost:4200'], //only when frontend is the case, or whatever you're planning to implement.
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization'],
  });
  console.log(`App is running on: http://localhost:3000`);
}
bootstrap();
