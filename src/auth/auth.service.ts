// src/auth/auth.service.ts
import {
  Injectable,
  UnauthorizedException,
  ForbiddenException,
  Logger,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UserService } from '../user/user.service';
import { PrismaService } from '../prisma/prisma.service';

const IP_WINDOW_SEC = 60;
const IP_FAIL_LIMIT = 5;
const USER_WINDOW_MIN = 1; // 1 dk ya düşürdüm ama en az 10 olmalı
const USER_FAIL_LIMIT = 10;
const DISTINCT_IP_WINDOW_MIN = 10;
const DISTINCT_IP_LIMIT = 3;
const LOCK_MIN = 30;

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
  ) {}

  // ---- REGISTER ----
  async register(email: string, password: string) {
    this.logger.debug(`Register attempt email=${email}`);

    const existing = await this.userService.findUserByEmail(email);
    if (existing) {
      this.logger.warn(`Register blocked: email already exists (${email})`);
      throw new UnauthorizedException('User already exists');
    }

    const user = await this.userService.createUser(email, password);
    this.logger.log(`User created id=${user.id}`);

    const tokens = this.generateTokens(user.id, user.email);
    await this.saveRefreshToken(user.id, tokens.refreshToken);

    this.logger.debug(`Tokens issued for user id=${user.id}`);
    return tokens; // { accessToken, refreshToken }
  }

  // ---- LOGIN (gelişmiş) ----
  async login(email: string, password: string, ip: string) {
    this.logger.debug(`Login attempt email=${email} ip=${ip}`);

    const now = new Date();

    // 0) IP kara listede mi?
    const ipBlock = await this.prisma.ipBlock.findUnique({ where: { ip } });
    if (ipBlock && ipBlock.blockUntil > now) {
      this.logger.warn(`Blocked IP attempted login: ${ip}`);
      throw new HttpException(
        'Too many attempts from this IP',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    // 1) Kullanıcı + hesap kilidi
    const user = await this.userService.findUserByEmail(email);
    if (user?.lockedUntil && user.lockedUntil > now) {
      this.logger.warn(
        `Account locked (email=${email}) until ${user.lockedUntil.toISOString()}`,
      );
      throw new ForbiddenException(
        'Account temporarily locked due to suspicious activity',
      );
    }

    // 2) IP kısa pencere
    const ipWindowStart = new Date(Date.now() - IP_WINDOW_SEC * 1000);
    const recentIpFails = await this.prisma.loginAttempt.count({
      where: { ip, success: false, createdAt: { gte: ipWindowStart } },
    });
    if (recentIpFails >= IP_FAIL_LIMIT) {
      await this.prisma.ipBlock.upsert({
        where: { ip },
        update: { blockUntil: new Date(Date.now() + 60 * 1000) },
        create: { ip, blockUntil: new Date(Date.now() + 60 * 1000) },
      });
      this.logger.warn(`IP temporarily blocked: ${ip}`);
      throw new HttpException(
        'Too many attempts from this IP',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    // 3) Kullanıcı pencere
    const userWindowStart = new Date(Date.now() - USER_WINDOW_MIN * 60 * 1000);
    const recentUserFails = await this.prisma.loginAttempt.count({
      where: { email, success: false, createdAt: { gte: userWindowStart } },
    });
    if (recentUserFails >= USER_FAIL_LIMIT && user) {
      await this.userService.updateUser(user.id, {
        lockedUntil: new Date(Date.now() + LOCK_MIN * 60 * 1000),
      });
      this.logger.warn(`User locked due to excessive failures: ${email}`);
      throw new ForbiddenException('Account temporarily locked');
    }

    // 4) Çoklu IP tespiti
    const distinctWindowStart = new Date(
      Date.now() - DISTINCT_IP_WINDOW_MIN * 60 * 1000,
    );
    const attempts = await this.prisma.loginAttempt.findMany({
      where: { email, success: false, createdAt: { gte: distinctWindowStart } },
      select: { ip: true },
    });
    const uniqueIpCount = new Set(attempts.map((a) => a.ip)).size;
    if (uniqueIpCount >= DISTINCT_IP_LIMIT && user) {
      // 4a) Hesabı kilitle
      await this.userService.updateUser(user.id, {
        lockedUntil: new Date(Date.now() + LOCK_MIN * 60 * 1000),
      });

      // 4b) Saldıran tüm IP’leri (benzersiz) kara listeye ekle
      const blockUntil = new Date(Date.now() + 60 * 1000); // örn. 60 sn
      const uniqueIps = Array.from(new Set(attempts.map((a) => a.ip)));

      for (const ipAddr of uniqueIps) {
        await this.prisma.ipBlock.upsert({
          where: { ip: ipAddr },
          update: { blockUntil },
          create: { ip: ipAddr, blockUntil },
        });
        this.logger.warn(`IP blocked (multi-IP attack): ${ipAddr}`);
      }

      throw new ForbiddenException(
        'Account temporarily locked due to suspicious activity',
      );
    }

    // 5) Parola doğrulama
    if (!user || !(await bcrypt.compare(password, user.password))) {
      await this.prisma.loginAttempt.create({
        data: { email, ip, success: false },
      });
      this.logger.warn(`Login failed email=${email} ip=${ip}`);
      throw new UnauthorizedException('Invalid credentials');
    }

    // 6) Başarılı giriş
    await this.prisma.$transaction(async (tx) => {
      await tx.loginAttempt.create({
        data: { email, ip, success: true },
      });

      await tx.user.update({
        where: { id: user.id },
        data: { lockedUntil: null },
      });
    });

    // 7) Token + refresh kaydet
    const tokens = this.generateTokens(user.id, user.email);
    await this.saveRefreshToken(user.id, tokens.refreshToken);

    this.logger.log(`Login success id=${user.id} ip=${ip}`);
    return tokens;
  }

  // ---- REFRESH ----
  async refreshAccessToken(refreshToken: string) {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });

      const user = await this.userService.findUserById(payload.sub);
      if (!user || !user.refreshToken) {
        this.logger.warn(
          `Refresh failed: user or token not found (sub=${payload.sub})`,
        );
        throw new UnauthorizedException('User or refresh token not found');
      }

      const isMatch = await bcrypt.compare(refreshToken, user.refreshToken);
      if (!isMatch) {
        this.logger.warn(`Refresh failed: token mismatch (sub=${payload.sub})`);
        throw new UnauthorizedException('Invalid refresh token');
      }

      const tokens = this.generateTokens(user.id, user.email);
      await this.saveRefreshToken(user.id, tokens.refreshToken);

      this.logger.log(`Refresh success id=${user.id}`);
      return tokens;
    } catch {
      this.logger.warn('Refresh failed: invalid/expired token');
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  // ---- LOGOUT ----
  async logout(userId: number) {
    await this.userService.updateUser(userId, { refreshToken: null });
    this.logger.log(`Logout success id=${userId}`);
    return { message: 'Logged out successfully' };
  }

  // ---- Helpers ----
  private generateTokens(userId: number, email: string) {
    const payload = { sub: userId, email };

    const accessToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_SECRET,
      expiresIn: '1h',
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_REFRESH_SECRET,
      expiresIn: '7d',
    });

    return { accessToken, refreshToken };
  }

  private async saveRefreshToken(userId: number, refreshToken: string) {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    await this.userService.updateUser(userId, {
      refreshToken: hashedRefreshToken,
    });
  }
}
