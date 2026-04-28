import { Controller, Get, Query } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Controller('metrics')
export class MetricsController {
  constructor(private prisma: PrismaService) {}

  // CHEAP-MEDIUM: tek count, indexli
  @Get('users/count')
  async usersCount() {
    const count = await this.prisma.user.count();
    return { count };
  }

  // EXPENSIVE: aggregate over LoginAttempt
  @Get('reports/login-stats')
  async loginStats(@Query('hours') hours: string = '24') {
    const since = new Date(Date.now() - parseInt(hours, 10) * 3600 * 1000);
    const [total, success, failure, byIp] = await Promise.all([
      this.prisma.loginAttempt.count({ where: { createdAt: { gte: since } } }),
      this.prisma.loginAttempt.count({ where: { createdAt: { gte: since }, success: true } }),
      this.prisma.loginAttempt.count({ where: { createdAt: { gte: since }, success: false } }),
      this.prisma.loginAttempt.groupBy({
        by: ['ip'],
        where: { createdAt: { gte: since } },
        _count: { _all: true },
        orderBy: { _count: { ip: 'desc' } },
        take: 10,
      }),
    ]);
    return { total, success, failure, topIps: byIp };
  }
}