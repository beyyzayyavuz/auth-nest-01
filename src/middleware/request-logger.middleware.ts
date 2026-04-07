import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { LogsService } from '../logs/logs.service';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';

@Injectable()
export class RequestLoggerMiddleware implements NestMiddleware {
  constructor(private logsService: LogsService) {}

  use(req: Request, res: Response, next: NextFunction) {
    // 1. Hassas zaman başlatma (ms bazında ölçüm için)
    const start = process.hrtime();
    const correlationId = uuidv4();

    res.on('finish', () => {
      // 2. Response Time Hesaplama
      const diff = process.hrtime(start);
      const responseTimeMs = parseFloat((diff[0] * 1e3 + diff[1] * 1e-6).toFixed(3));

      // 3. IP ve User-Agent Yakalama
      const userAgent = req.headers['user-agent'] || 'unknown';
      const ip = (req.headers['x-forwarded-for'] as string) || req.ip || req.socket.remoteAddress || 'unknown';

      // 4. Client Fingerprint (IAT Analizi için kritik)
      // IP ve User-Agent'ı birleştirip hash'liyoruz
      const clientHash = crypto
        .createHash('md5')
        .update(ip + userAgent)
        .digest('hex');

      // 5. Route Template (Maliyet Analizi için kritik)
      // NestJS route yapısını (/user/:id gibi) yakalamaya çalışır, yoksa ham URL'i temizler
      const routeTemplate = req.route ? req.route.path : req.originalUrl.split('?')[0];

      // 6. Veriyi Hazırlama (Prisma Modelinle Birebir Uyumlu)
      const logEntry = {
        correlationId,
        clientHash,
        ip,
        userAgent,
        method: req.method,
        routeTemplate,
        url: req.originalUrl,
        statusCode: res.statusCode,
        responseTimeMs,
        payloadSize: parseInt(req.headers['content-length'] || '0'),
        headerSize: JSON.stringify(req.headers).length,
        trafficLabel: (req.headers['x-simulation-label'] as string) || 'unlabeled',
        timestamp: new Date(),
      };

      // 7. Servise Gönder (Asenkron ve Batch işleme uygun)
      this.logsService.saveLog(logEntry).catch((err) => {
        console.error('[Middleware Error] Log could not be passed to service:', err.message);
      });
    });

    next();
  }
}