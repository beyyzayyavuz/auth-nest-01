import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { LogsService } from '../logs/logs.service';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';

@Injectable()
export class RequestLoggerMiddleware implements NestMiddleware {
  constructor(private logsService: LogsService) {}

  use(req: Request, res: Response, next: NextFunction) {
    const start = process.hrtime();
    const correlationId = uuidv4();
    const startTime = Date.now();

    res.on('finish', () => {
      const diff = process.hrtime(start);
      const responseTimeMs = parseFloat(
        (diff[0] * 1e3 + diff[1] * 1e-6).toFixed(3),
      );

      const duration = Date.now() - startTime;

      const rawLabel = req.headers['x-simulation-label'];
      const label = Array.isArray(rawLabel)
        ? rawLabel[0]
        : (rawLabel || 'unknown');

      console.log(
        `[${String(label).toUpperCase()}] ${req.method} ${req.url} => Status: ${res.statusCode} (${duration}ms)`,
      );

      const userAgent = Array.isArray(req.headers['user-agent'])
        ? req.headers['user-agent'][0]
        : (req.headers['user-agent'] || 'unknown');

      const ip = this.resolveClientIp(req);

      const clientHash = crypto
        .createHash('md5')
        .update(`${String(ip)}|${String(userAgent)}`)
        .digest('hex');

      const routeTemplate =
        req.baseUrl && req.route?.path
          ? `${req.baseUrl}${req.route.path}`
          : req.route?.path || req.originalUrl.split('?')[0];

      const logEntry = {
        correlationId,
        clientHash,
        ip,
        userAgent: String(userAgent),
        method: req.method,
        routeTemplate,
        url: req.originalUrl,
        statusCode: res.statusCode,
        responseTimeMs,
        payloadSize: parseInt(String(req.headers['content-length'] || '0'), 10),
        headerSize: JSON.stringify(req.headers).length,
        trafficLabel: String(label || 'unlabeled'),
        timestamp: new Date(),
      };

      this.logsService.saveLog(logEntry).catch((err) => {
        console.error(
          '[Middleware Error] Log could not be passed to service:',
          err.message,
        );
      });
    });

    next();
  }

  private resolveClientIp(req: Request): string {
    const allowTestIpHeader = process.env.ALLOW_TEST_IP_HEADER === 'true';

    const rawTestClientIp = req.headers['x-test-client-ip'];
    const testClientIp = Array.isArray(rawTestClientIp)
      ? rawTestClientIp[0]?.trim()
      : String(rawTestClientIp || '').trim();

    const rawForwardedFor = req.headers['x-forwarded-for'];
    const forwardedFor = Array.isArray(rawForwardedFor)
      ? rawForwardedFor[0]
      : rawForwardedFor;

    const forwardedIp = forwardedFor
      ? String(forwardedFor).split(',')[0].trim()
      : undefined;

    const validTestIp =
      allowTestIpHeader && this.isValidIpv4(testClientIp)
        ? testClientIp
        : undefined;

    return (
      validTestIp ||
      forwardedIp ||
      req.ip ||
      req.socket.remoteAddress ||
      'unknown'
    );
  }

  private isValidIpv4(ip?: string): boolean {
    if (!ip) return false;

    const ipv4Regex =
      /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

    return ipv4Regex.test(ip);
  }
}