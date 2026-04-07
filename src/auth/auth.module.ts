import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UserModule } from '../user/user.module';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtStrategy } from './jwt.strategy';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [
  ConfigModule.forRoot({ isGlobal: true }), // 🔹 isGlobal: true önemli
  UserModule,
  PrismaModule,
  JwtModule.register({
    secret: process.env.JWT_SECRET, // burada artık configService kullanabilirsin
    signOptions: { expiresIn: '1h' },
  }),
],
  providers: [AuthService, JwtStrategy],
  controllers: [AuthController],
})
export class AuthModule {}