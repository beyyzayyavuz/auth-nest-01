import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { LogsService } from '../logs/logs.service';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import { UAParser } from 'ua-parser-js';
import { performance } from 'perf_hooks';
import { requestContext, RequestMetrics } from '../common/request-context/request-context';

@Injectable()
export class RequestLoggerMiddleware implements NestMiddleware {
  constructor(private logsService: LogsService) {}

  // İstek kapıdan girdiği an kronometreyi ve işlemci sayaçlarını başlatan, istek bittiği an ise loglama sürecini tetikleyen ana giriş kapısıdır.
  use(req: Request, res: Response, next: NextFunction) {
    const correlationId = uuidv4();
    const tRecv = Date.now();
    const start = process.hrtime();
    const cpuStart = process.cpuUsage();

    // Bu request için izole metrics objesi
    const metrics: RequestMetrics = {
      dbQueryCount: 0,
      dbTotalTimeMs: 0,
      externalCallCount: 0,
      tRecv,
      tHandlerStart: 0,
      tHandlerEnd: 0,
      cpuStart,
    };

    // Response bittiğinde Prisma RequestLog'a yaz
    res.on('finish', () => {
      const diff = process.hrtime(start);
      const responseTimeMs = parseFloat(
        (diff[0] * 1e3 + diff[1] * 1e-6).toFixed(3),
      );
      const cpuDiff = process.cpuUsage(cpuStart);
      const cpuTimeMs = (cpuDiff.user + cpuDiff.system) / 1000;

      this.writeLog(req, res, metrics, cpuTimeMs, responseTimeMs, correlationId);
    });

    // Tüm request handling AsyncLocalStorage scope'unda — Prisma queries
    // metrics objesini görsün diye
    requestContext.run(metrics, () => {
      next();
    });
  }

  // İstek tamamlandığında, request ve response objelerinden, ayrıca middleware'in başında başlatılan kronometre ve işlemci sayaçlarından çeşitli bilgileri toplayarak LogsService aracılığıyla veritabanına kaydeder.
  private writeLog(
    req: Request,
    res: Response,
    metrics: RequestMetrics,
    cpuTimeMs: number,
    responseTimeMs: number,
    correlationId: string,
  ) {
    const rawLabel = req.headers['x-simulation-label'];
    const label = Array.isArray(rawLabel)
      ? rawLabel[0]
      : (rawLabel || 'unknown');

    const userAgent = Array.isArray(req.headers['user-agent'])
      ? req.headers['user-agent'][0]
      : (req.headers['user-agent'] || 'unknown');

    // ua-parser-js ile family extract et
    const parser = new UAParser(String(userAgent));
    const browser = parser.getBrowser();
    const uaFamily = browser.name || 'unknown';

    const uaRawHash = crypto
      .createHash('sha256')
      .update(String(userAgent))
      .digest('hex')
      .slice(0, 32);

    const ip = this.resolveClientIp(req);
    const ipSubnet24 = ip.includes('.')
      ? ip.split('.').slice(0, 3).join('.') + '.0'
      : null;

    const clientHash = crypto
      .createHash('md5')
      .update(`${String(ip)}|${String(userAgent)}`)
      .digest('hex');

    const routeTemplate =
      req.baseUrl && req.route?.path
        ? `${req.baseUrl}${req.route.path}`
        : req.route?.path || req.originalUrl.split('?')[0];

    // Header sayımı
    const headerCount = Object.keys(req.headers).length;

    // Header presence'ları
    const refererPresent = !!req.headers['referer'];
    const cookiePresent = !!req.headers['cookie'];
    const acceptLangPresent = !!req.headers['accept-language'];
    const acceptEncPresent = !!req.headers['accept-encoding'];

    // Accept set hash (UA + Lang + Enc tuple cardinality için)
    const acceptComponents = [
      String(req.headers['accept'] || ''),
      String(req.headers['accept-language'] || ''),
      String(req.headers['accept-encoding'] || ''),
    ].join('|');
    const acceptSetHash = crypto
      .createHash('md5')
      .update(acceptComponents)
      .digest('hex')
      .slice(0, 16);

    // Body length received
    const contentLength = req.headers['content-length'];
    const bodyLenReceived = contentLength
      ? parseInt(String(contentLength), 10) || 0
      : 0;

    // Query string length
    const queryStrLen = req.originalUrl.includes('?')
      ? req.originalUrl.split('?')[1].length
      : 0;

    // Session ve login info
    const userId = (req as any).user?.userId;
    const sessionIdHash = userId
      ? crypto.createHash('sha256').update(String(userId)).digest('hex').slice(0, 32)
      : null;
    const loginPresent = !!userId;

    // Connection info — nginx tarafından inject edilen header'lardan
    const connId = String(req.headers['x-connection-id'] || '');
    const connReqStr = String(req.headers['x-connection-req'] || '');
    const connRequestIndex = connReqStr ? parseInt(connReqStr, 10) || null : null;

    // Partial request flag (slowloris signature) — status'a bakarak
    const partialRequest = [400, 408, 444, 499].includes(res.statusCode);

    // Scenario id (varsa traffic generator header'ından)
    const scenarioId = String(req.headers['x-scenario-id'] || '') || null;

    const logEntry = {
      correlationId,
      clientHash,
      ip,
      ipSubnet24,
      userAgent: String(userAgent),
      uaFamily,
      uaRawHash,
      method: req.method,
      routeTemplate,
      url: req.originalUrl,
      queryStrLen,
      bodyLenReceived,
      statusCode: res.statusCode,
      responseTimeMs,
      payloadSize: bodyLenReceived,  // backwards compat
      headerSize: JSON.stringify(req.headers).length,
      headerCount,
      refererPresent,
      cookiePresent,
      acceptLangPresent,
      acceptEncPresent,
      acceptSetHash,
      dbQueryCount: metrics.dbQueryCount,
      dbTotalTimeMs: metrics.dbTotalTimeMs,
      cpuTimeMs,
      externalCallCount: metrics.externalCallCount,
      connId: connId || null,
      connRequestIndex,
      sessionIdHash,
      loginPresent,
      partialRequest,
      trafficLabel: String(label || 'unlabeled'),
      scenarioId,
      timestamp: new Date(),
    };

    this.logsService.saveLog(logEntry).catch((err) => {
      console.error('[Middleware] Log save failed:', err.message);
    });
  }

  // İstek NGINX proxy'sinden geçtiği için gerçek kullanıcının IP adresini doğru tespit etmeye yarayan IP çözücü ve doğrulayıcı yardımcı fonksiyondur.
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

  // Basit bir IPv4 doğrulayıcıdır. Test IP header'ının geçerli bir IPv4 adresi içerip içermediğini kontrol etmek için kullanılır. Bu, özellikle test ve staging ortamlarında, gerçek IP adreslerini taklit etmek için x-test-client-ip header'ını kullanan senaryolarda önemlidir.
  private isValidIpv4(ip?: string): boolean {
    if (!ip) return false;
    const ipv4Regex =
      /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
    return ipv4Regex.test(ip);
  }
}