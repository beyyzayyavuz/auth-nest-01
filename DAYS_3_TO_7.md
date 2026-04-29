# DAYS 3 → 7 — Week 1 Devamı

Bu dosya Day 3 (instrumentation), Day 4 (log ingestion), Day 5 (NASA dataset
parse), Day 6 (Markov + endpoint mapping) ve Day 7 (Week 1 final checkpoint)
adımlarını içerir.

> Tüm komutlar projenin kök dizininde (`/Users/beyzayavuz/Desktop/auth-nest-01`).
> Her adım sonunda **sanity test** var, geçmeden devam etme.
> Takıldığında "Common errors" bölümlerine bak.

---

## Pre-flight: Day 1+2 hâlâ çalışıyor mu?

Day 3'e başlamadan önce doğrula:

```bash
# Postgres + nginx ayakta mı?
docker compose ps

# NestJS çalışıyor mu? (Yeni terminal)
npm run start:dev

# 4 cost class hâlâ tepki veriyor mu?
curl -s http://localhost:8080/health
curl -s http://localhost:8080/metrics/users/count
```

Hepsi yanıt verdiyse devam.

---

## DAY 3 — Backend Cost Instrumentation

**Hedef:** Nginx access log'unda boş kalan `x_db_query_count`, `x_db_total_time_ms`,
`x_cpu_time_ms`, `x_route_template`, `x_session_id_hash`, `x_login_present`,
`x_t_recv`, `x_t_handler_start`, `x_t_handler_end` alanları dolacak. RequestLog
tablosuna da aynı veriler yazılacak.

**Yapı:**

```
Request
  → BackendCostInterceptor (handler öncesi: cpuStart, tHandlerStart, ALS context oluştur)
    → Prisma queries ($on('query') hook ALS context'inden RequestMetrics'i bulur, sayar)
  → BackendCostInterceptor (handler sonrası: response header'ları set et)
  → Express res.on('finish')
    → RequestLoggerMiddleware (response header'ları okur, RequestLog'a yazar)
  → Nginx (response header'ları $sent_http_x_* ile access log'a yazar)
```

### 3.1 ua-parser-js paketini kur

User-Agent string'inden `uaFamily` türetmek için.

```bash
npm install ua-parser-js
npm install -D @types/ua-parser-js
```

### 3.2 AsyncLocalStorage Request Context oluştur

Yeni dosya: `src/common/request-context/request-context.ts`

```typescript
import { AsyncLocalStorage } from 'async_hooks';

export interface RequestMetrics {
  dbQueryCount: number;
  dbTotalTimeMs: number;
  externalCallCount: number;
  cpuStart: NodeJS.CpuUsage;
  tHandlerStart: number;  // performance.now() at interceptor entry
  tRecvMs: number;        // epoch ms when request entered the system
}

export const requestContext = new AsyncLocalStorage<RequestMetrics>();
```

> Bu modül sadece bir global ALS instance'ı export eder. Hem interceptor hem
> Prisma hook bu instance'tan oku/yaz yapacak.

### 3.3 PrismaService'i `$on('query')` hook'u ile genişlet

`src/prisma/prisma.service.ts` dosyasını **şununla değiştir** (mevcut bare-bones
versiyonu kaybetmiyoruz, üzerine ekliyoruz):

```typescript
import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient, Prisma } from '@prisma/client';
import { requestContext } from '../common/request-context/request-context';

@Injectable()
export class PrismaService
  extends PrismaClient<Prisma.PrismaClientOptions, 'query'>
  implements OnModuleInit, OnModuleDestroy
{
  constructor() {
    super({
      log: [{ emit: 'event', level: 'query' }],
    });
  }

  async onModuleInit() {
    // Her Prisma query'sinde event ateşlenir; ALS context varsa metric'i biriktir
    this.$on('query', (e) => {
      const ctx = requestContext.getStore();
      if (!ctx) return; // Context yok = arka plan task'ı, kaydetme
      ctx.dbQueryCount += 1;
      ctx.dbTotalTimeMs += e.duration; // ms cinsinden
    });

    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}
```

> **Not:** Prisma TypeScript typing'inde `$on('query')` event payload'ı için
> generic gerek; `extends PrismaClient<Prisma.PrismaClientOptions, 'query'>`
> ile `e: Prisma.QueryEvent` tipini doğru çıkarıyoruz.

> **Bilinmesi gereken:** Bu hook **Prisma seviyesindeki query'leri** yakalar.
> `prisma.user.count()`, `prisma.loginAttempt.create()` gibi çağrılar ✓.
> `$queryRaw` ile yazılan ham SQL çağrıları da yakalar ✓. Ancak Prisma'nın
> internal migration query'leri ya da connection pool maintenance query'leri
> belki yakalanmaz; bu **kabul edilebilir** çünkü bizim ölçtüğümüz "user-induced
> backend cost".

### 3.4 BackendCostInterceptor oluştur

Yeni dosya: `src/common/interceptors/backend-cost.interceptor.ts`

```typescript
import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { performance } from 'perf_hooks';
import { createHash } from 'crypto';
import {
  requestContext,
  RequestMetrics,
} from '../request-context/request-context';

@Injectable()
export class BackendCostInterceptor implements NestInterceptor {
  intercept(ctx: ExecutionContext, next: CallHandler): Observable<any> {
    const httpCtx = ctx.switchToHttp();
    const req = httpCtx.getRequest();
    const res = httpCtx.getResponse();

    // tRecv: nginx'in proxy_set_header X-Recv-Start ile gönderdiği epoch (saniye+ms)
    const tRecvHeader = req.headers['x-recv-start'];
    const tRecvMs = tRecvHeader
      ? parseFloat(String(tRecvHeader)) * 1000
      : Date.now();

    const metrics: RequestMetrics = {
      dbQueryCount: 0,
      dbTotalTimeMs: 0,
      externalCallCount: 0,
      cpuStart: process.cpuUsage(),
      tHandlerStart: performance.now(),
      tRecvMs,
    };

    // ALS context'i Observable subscription chain'i boyunca aktif tut
    return new Observable<any>((subscriber) => {
      let subscription: any;
      requestContext.run(metrics, () => {
        subscription = next.handle().subscribe({
          next: (val) => subscriber.next(val),
          error: (err) => {
            this.writeHeaders(req, res, metrics);
            subscriber.error(err);
          },
          complete: () => {
            this.writeHeaders(req, res, metrics);
            subscriber.complete();
          },
        });
      });
      return () => subscription?.unsubscribe();
    });
  }

  private writeHeaders(req: any, res: any, m: RequestMetrics) {
    if (res.headersSent) return; // çok geç, header'lar gitti

    const tHandlerEnd = performance.now();
    const cpuDiff = process.cpuUsage(m.cpuStart);
    const cpuTimeMs = (cpuDiff.user + cpuDiff.system) / 1000;

    // Route template: NestJS request.route?.path; baseUrl varsa prepend
    const routeTemplate =
      req.route?.path
        ? `${req.baseUrl || ''}${req.route.path}`
        : req.originalUrl?.split('?')[0] || 'unknown';

    // Session id: JWT subject'ten (req.user.userId, JwtStrategy.validate set ediyor)
    const userId = req.user?.userId;
    const sessionIdHash = userId
      ? createHash('sha256').update(String(userId)).digest('hex').slice(0, 32)
      : '';
    const loginPresent = userId ? '1' : '0';

    res.setHeader('X-Route-Template', routeTemplate);
    res.setHeader('X-DB-Query-Count', String(m.dbQueryCount));
    res.setHeader('X-DB-Total-Time-Ms', m.dbTotalTimeMs.toFixed(2));
    res.setHeader('X-CPU-Time-Ms', cpuTimeMs.toFixed(2));
    res.setHeader('X-External-Call-Count', String(m.externalCallCount));
    res.setHeader('X-Session-Id-Hash', sessionIdHash);
    res.setHeader('X-Login-Present', loginPresent);
    res.setHeader('X-T-Recv', String(m.tRecvMs));
    res.setHeader('X-T-Handler-Start', m.tHandlerStart.toFixed(3));
    res.setHeader('X-T-Handler-End', tHandlerEnd.toFixed(3));
  }
}
```

### 3.5 Interceptor'ı global olarak register et

`src/main.ts` dosyasını şöyle güncelle:

```typescript
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
  logger.log('Application is starting...');

  // GLOBAL INTERCEPTOR — tüm endpoint'lere uygulansın
  app.useGlobalInterceptors(new BackendCostInterceptor());

  app.enableCors({
    origin: ['http://localhost:4200'],
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  await app.listen(3000);
  logger.log('Application is running on: http://localhost:3000');
}
bootstrap();
```

> Eski `console.log('SİSTEM TERMİNALİNDEKİ SECRET:', process.env.JWT_SECRET);`
> satırı varsa **silmen önerilir** (security hygiene). Tezde production'da
> JWT secret'ı log'lamak istemezsin.

### 3.6 RequestLoggerMiddleware'i extend et

`src/middleware/request-logger.middleware.ts` dosyasını **şununla değiştir**.
Mevcut middleware'in tüm fonksiyonlarını koruyor + yeni alanları dolduruyor:

```typescript
import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { LogsService } from '../logs/logs.service';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import { UAParser } from 'ua-parser-js';

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

      // Traffic label
      const rawLabel = req.headers['x-simulation-label'];
      const label = Array.isArray(rawLabel)
        ? rawLabel[0]
        : rawLabel || 'unknown';

      // Scenario id (k6 traffic generator'lar veya orchestrator gönderebilir)
      const rawScenarioId = req.headers['x-scenario-id'];
      const scenarioId = Array.isArray(rawScenarioId)
        ? rawScenarioId[0]
        : (rawScenarioId as string) || null;

      // User-Agent
      const userAgent = Array.isArray(req.headers['user-agent'])
        ? req.headers['user-agent'][0]
        : req.headers['user-agent'] || 'unknown';
      const uaParsed = new UAParser(String(userAgent));
      const uaFamily = uaParsed.getBrowser().name || this.classifyUA(String(userAgent));
      const uaRawHash = crypto
        .createHash('sha256')
        .update(String(userAgent))
        .digest('hex')
        .slice(0, 32);

      // IP
      const ip = this.resolveClientIp(req);
      const ipSubnet24 = this.computeSubnet24(ip);

      // Client hash
      const clientHash = crypto
        .createHash('md5')
        .update(`${ip}|${userAgent}`)
        .digest('hex');

      // Headers
      const headerCount = Object.keys(req.headers).length;
      const refererPresent = !!req.headers['referer'];
      const cookiePresent = !!req.headers['cookie'];
      const acceptLangPresent = !!req.headers['accept-language'];
      const acceptEncPresent = !!req.headers['accept-encoding'];

      const acceptSetHash = crypto
        .createHash('md5')
        .update(
          [
            req.headers['accept'] || '',
            req.headers['accept-language'] || '',
            req.headers['accept-encoding'] || '',
          ].join('|'),
        )
        .digest('hex')
        .slice(0, 16);

      // Body / query
      const queryStrLen = req.url.includes('?')
        ? req.url.split('?')[1].length
        : 0;
      const contentLength = parseInt(
        String(req.headers['content-length'] || '0'),
        10,
      );
      const bodyLenReceived = contentLength;

      // Connection (nginx proxy_set_header X-Connection-Id, X-Connection-Req)
      const connId = (req.headers['x-connection-id'] as string) || null;
      const connRequestIndexRaw = req.headers['x-connection-req'];
      const connRequestIndex = connRequestIndexRaw
        ? parseInt(String(connRequestIndexRaw), 10)
        : null;

      // Backend cost — interceptor'ın set ettiği response header'lardan oku
      const dbQueryCount = parseInt(
        String(res.getHeader('X-DB-Query-Count') || '0'),
        10,
      );
      const dbTotalTimeMs = parseFloat(
        String(res.getHeader('X-DB-Total-Time-Ms') || '0'),
      );
      const cpuTimeMs = parseFloat(
        String(res.getHeader('X-CPU-Time-Ms') || '0'),
      );
      const externalCallCount = parseInt(
        String(res.getHeader('X-External-Call-Count') || '0'),
        10,
      );

      // Session
      const sessionIdHash =
        (res.getHeader('X-Session-Id-Hash') as string) || null;
      const loginPresent =
        String(res.getHeader('X-Login-Present') || '0') === '1';

      // Route template (interceptor doldurmuşsa onu kullan, yoksa fallback)
      const routeTemplateFromHeader = res.getHeader(
        'X-Route-Template',
      ) as string;
      const routeTemplate =
        routeTemplateFromHeader ||
        (req.baseUrl && req.route?.path
          ? `${req.baseUrl}${req.route.path}`
          : req.route?.path || req.originalUrl.split('?')[0]);

      // Partial request indicator (slowloris signature placeholder)
      const partialRequest = [400, 408, 444, 499].includes(res.statusCode);

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
        payloadSize: contentLength,
        headerSize: JSON.stringify(req.headers).length,
        headerCount,
        refererPresent,
        cookiePresent,
        acceptLangPresent,
        acceptEncPresent,
        acceptSetHash,
        dbQueryCount,
        dbTotalTimeMs,
        cpuTimeMs,
        externalCallCount,
        connId,
        connRequestIndex,
        sessionIdHash,
        loginPresent,
        partialRequest,
        trafficLabel: String(label),
        scenarioId,
        timestamp: new Date(),
      };

      // Existing console output (debug)
      console.log(
        `[${String(label).toUpperCase()}] ${req.method} ${req.url} => ${res.statusCode} (${responseTimeMs}ms, db=${dbQueryCount}q/${dbTotalTimeMs}ms, cpu=${cpuTimeMs}ms)`,
      );

      this.logsService.saveLog(logEntry).catch((err) => {
        console.error(
          '[Middleware Error] Log could not be passed to service:',
          err.message,
        );
      });
    });

    next();
  }

  // --- Helpers ---

  private classifyUA(ua: string): string {
    // ua-parser-js bilmediği botları tanımaz; basit fallback
    const lc = ua.toLowerCase();
    if (lc.includes('curl')) return 'curl';
    if (lc.includes('python-requests')) return 'python-requests';
    if (lc.includes('go-http-client')) return 'go-http';
    if (lc.includes('postman')) return 'postman';
    if (lc.includes('bot')) return 'bot';
    if (lc.includes('k6')) return 'k6';
    return 'unknown';
  }

  private computeSubnet24(ip: string): string | null {
    if (!ip || ip === 'unknown') return null;
    // IPv4 only — IPv6 v1 scope dışı
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
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
```

### 3.7 LogsService Prisma input tipi güncellemesi

`src/logs/logs.service.ts` mevcut hâliyle `Prisma.RequestLogCreateInput` tipini
kullanıyor. Schema yeni alanlarla genişlediği için Prisma generate sonrası
otomatik tip güncellemesi olur. Ama kontrol et:

```bash
npx prisma generate
```

`@prisma/client`'ın yeni tip tanımları middleware'in döndürdüğü objeyi kabul
etmeli. Eğer TypeScript "property X is missing" hatası verirse, Prisma generate
yapılmamış demektir.

### 3.8 Sanity test — Day 3 tamam mı?

NestJS hot-reload yapıp tekrar başlatmalı (start:dev terminalinde). Yeniden
başlamazsa Ctrl+C, `npm run start:dev` ile manuel başlat.

```bash
# 5 farklı endpoint'e label'lı istek at
for ep in /health /ping /metrics/users/count "/metrics/reports/login-stats?hours=24"; do
  curl -s -H "x-simulation-label: instr-test" "http://localhost:8080${ep}" > /dev/null
done

sleep 6  # LogsService flush

# Hem nginx log'da hem RequestLog'da yeni alanlar dolu mu?
echo "=== nginx log son 5 satır (yeni alanlar dolu mu?) ==="
tail -n 5 infra/nginx/logs/ddos_research.log | python3 -c "
import sys, json
for line in sys.stdin:
    d = json.loads(line)
    print(f\"  {d['request_uri']:40} db_q={d['x_db_query_count']:>3} db_ms={d['x_db_total_time_ms']:>6} cpu={d['x_cpu_time_ms']:>5} route={d['x_route_template']}\")
"

echo
echo "=== RequestLog yeni alanlar ==="
docker compose exec postgres psql -U research -d ddos_research -c "
SELECT \"routeTemplate\", \"dbQueryCount\", \"dbTotalTimeMs\", \"cpuTimeMs\",
       \"uaFamily\", \"ipSubnet24\", \"loginPresent\"
FROM \"RequestLog\"
WHERE \"trafficLabel\"='instr-test'
ORDER BY timestamp DESC LIMIT 5;"
```

**Beklenen:**
- nginx log'da `x_db_query_count` /metrics/users/count için `1`,
  /metrics/reports/login-stats için `4`, /health ve /ping için `0`
- RequestLog'da `dbQueryCount`, `dbTotalTimeMs`, `cpuTimeMs` hepsi sıfırdan
  büyük (en azından metrics endpoint'leri için)
- `uaFamily` curl çağrılarında `curl` görünmeli
- `ipSubnet24` `192.168.65.0/24` benzeri (Docker bridge subnet)

Eğer bu çalışıyorsa **Day 3 tamam**.

### Day 3 — Common errors

**E1: nginx log'da `x_db_query_count` hâlâ boş.**

Sebep: NestJS'in response header'ları nginx'e ulaşmıyor. Üç olasılık:

```bash
# Test 1: NestJS gerçekten header set ediyor mu?
curl -i http://localhost:3000/metrics/users/count | grep -i "x-db"

# Eğer header görünüyorsa NestJS OK, sorun nginx'te.
# Eğer görünmüyorsa interceptor register olmamış (main.ts kontrol)
```

```bash
# Test 2: nginx upstream'i headeral'arı geçiriyor mu?
docker compose exec nginx nginx -t
docker compose restart nginx
```

`infra/nginx/nginx.conf` içinde `proxy_hide_header X-DB-Query-Count` satırı
var, bu header'ı **client'a gizliyor** ama nginx kendi log'una yazıyor (önce
log, sonra hide). Yine de kontrol et.

**E2: `dbQueryCount` her zaman 0.**

Sebep: AsyncLocalStorage context Prisma hook'a propagate olmuyor. Bu Node 14+'da
default çalışmalı. Eğer çalışmıyorsa Prisma version kontrol et:

```bash
npm list @prisma/client
```

Prisma 5.0+ olmalı. Daha eski sürümlerde `$on('query')` ALS ile çalışmayabilir.
Mevcut sende 6.12 → bu sorun olmaması gerek.

**E3: `req.user` undefined, `loginPresent` hep `false`.**

Sebep: JwtAuthGuard sadece `@UseGuards(JwtAuthGuard)` annotated endpoint'lerde
`req.user` set eder. `/health`, `/ping` gibi public endpoint'lerde set etmez.
Bu **doğru davranış**. Login flow'u içeren endpoint'ler (örneğin sonradan
auth-only endpoint çağrılırsa) `loginPresent: true` olacak.

**E4: TypeScript "property X does not exist" hataları.**

`npx prisma generate` çalıştır. Schema değişikliği sonrası tip cache
güncellenmeli.

### Day 3 commit

```bash
git add -A
git commit -m "Day 3 complete: backend cost instrumentation (ALS + Prisma hook + interceptor + middleware extend)"
```

---

## DAY 4 — Log Ingestion + Connection-level Merge

**Hedef:** Şu an iki log path'ı var (nginx access log JSON + RequestLog tablosu).
Bu ikisini birleştir ve connection-level (Tier 1) feature'ları türet.

**Yapı:**

```
nginx access log (JSON satırları)
  ↓ Python tail script
PostgreSQL'e ham parse
  ↓ Aggregate by conn_id
Connection tablosu doldur (mean_request_time_ms, partial_request_count, vs.)
```

> **Not:** RequestLog tablosu zaten NestJS middleware'inden dolduruluyor.
> nginx log'unu **ayrı olarak** tutmamız sebebi: nginx'in connection-level
> verisini (`$connection`, `$connection_requests`) NestJS göremez. Day 4'te
> bunları nginx log'undan çıkarıyoruz.

### 4.1 Python venv setup

```bash
mkdir -p scripts
cd scripts

python3 -m venv venv
source venv/bin/activate

pip install psycopg2-binary pandas
```

İlerideki day'lerde de bu venv'i kullanacağız (Day 5 NASA parse, vs.).

### 4.2 Nginx log → PostgreSQL ingester

Yeni dosya: `scripts/ingest_nginx_log.py`

```python
"""
Nginx access log JSON → Postgres senkronu.
- ddos_research.log dosyasını tail eder
- her satırı parse eder
- mevcut RequestLog satırı varsa connection alanlarını UPDATE eder
- yeni satırları yok sayar (NestJS middleware zaten yazdı)
- connection bazında aggregate'leri Connection tablosuna yazar (periyodik)
"""

import json
import time
import os
import sys
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import psycopg2
from psycopg2.extras import execute_batch

DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'user': 'research',
    'password': 'research',
    'dbname': 'ddos_research',
}

LOG_PATH = '../infra/nginx/logs/ddos_research.log'
FLUSH_INTERVAL_SEC = 5
CONN_AGG_INTERVAL_SEC = 30


def parse_msec(value):
    """nginx $msec is 'sec.ms' epoch float as string."""
    if not value:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (ValueError, TypeError):
        return None


def parse_int(value, default=0):
    try:
        return int(value) if value not in (None, '', '-') else default
    except (ValueError, TypeError):
        return default


def parse_float(value, default=0.0):
    try:
        return float(value) if value not in (None, '', '-') else default
    except (ValueError, TypeError):
        return default


def open_log(path):
    """Tail'a benzer: dosyayı açar, sonuna git, yeni satırları yield eder."""
    f = open(path, 'r')
    f.seek(0, os.SEEK_END)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line.strip()


def update_connection_fields(conn, batch):
    """RequestLog'da mevcut satırların connection alanlarını günceller."""
    if not batch:
        return
    sql = """
    UPDATE "RequestLog"
    SET "connId" = %(conn_id)s,
        "connRequestIndex" = %(conn_req_idx)s,
        "partialRequest" = %(partial)s
    WHERE "correlationId"::text = %(correlation_id)s
       OR ("ip" = %(remote_addr)s AND "url" = %(uri)s
           AND ABS(EXTRACT(EPOCH FROM ("timestamp" - %(t_recv)s))) < 1)
    """
    with conn.cursor() as cur:
        execute_batch(cur, sql, batch, page_size=50)
    conn.commit()


def aggregate_connections(conn, log_buffer):
    """
    Bir connection_id için tüm gözlenen request'leri aggregate eder,
    Connection tablosuna upsert yapar.
    """
    by_conn = defaultdict(list)
    for entry in log_buffer:
        conn_id = entry.get('connection')
        if conn_id and conn_id != '-':
            by_conn[conn_id].append(entry)

    upserts = []
    for conn_id, entries in by_conn.items():
        if not entries:
            continue

        first = min(entries, key=lambda e: parse_float(e.get('t_recv_start')))
        last = max(entries, key=lambda e: parse_float(e.get('t_recv_start')))

        request_times = [
            parse_float(e.get('request_time')) * 1000 for e in entries
        ]
        request_times.sort()

        partial_count = sum(
            1 for e in entries
            if parse_int(e.get('status')) in (400, 408, 444, 499)
        )
        timeout_count = sum(
            1 for e in entries if parse_int(e.get('status')) == 408
        )

        request_lengths = [parse_int(e.get('request_length')) for e in entries]
        total_bytes = sum(request_lengths)

        t_open = parse_msec(first.get('t_recv_start'))
        t_close = parse_msec(last.get('t_recv_start'))
        duration_ms = (
            int((t_close - t_open).total_seconds() * 1000)
            if t_open and t_close else None
        )

        ip = first.get('remote_addr') or 'unknown'
        ip_parts = ip.split('.')
        ip_subnet_24 = (
            f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            if len(ip_parts) == 4 else None
        )

        scenario_id = first.get('x_scenario_id') or None

        upserts.append({
            'id': conn_id,
            'scenario_id': scenario_id,
            'ip': ip,
            'ip_subnet_24': ip_subnet_24,
            't_open': t_open,
            't_close': t_close,
            'duration_ms': duration_ms,
            'request_count': len(entries),
            'keepalive_used': len(entries) > 1,
            'mean_request_time_ms': (
                sum(request_times) / len(request_times)
                if request_times else None
            ),
            'p95_request_time_ms': (
                request_times[int(len(request_times) * 0.95)]
                if request_times else None
            ),
            'max_request_time_ms': max(request_times) if request_times else None,
            'mean_inbound_byte_rate': (
                total_bytes / (duration_ms / 1000)
                if duration_ms and duration_ms > 0 else None
            ),
            'partial_request_count': partial_count,
            'timeout_request_count': timeout_count,
            'tls_version': first.get('ssl_protocol') or None,
            'tls_cipher': first.get('ssl_cipher') or None,
        })

    if not upserts:
        return

    sql = """
    INSERT INTO "Connection" (
        id, "scenarioId", ip, "ipSubnet24", "tOpen", "tClose", "durationMs",
        "requestCount", "keepaliveUsed", "meanRequestTimeMs", "p95RequestTimeMs",
        "maxRequestTimeMs", "meanInboundByteRate", "partialRequestCount",
        "timeoutRequestCount", "tlsVersion", "tlsCipher"
    ) VALUES (
        %(id)s, %(scenario_id)s, %(ip)s::inet, %(ip_subnet_24)s, %(t_open)s,
        %(t_close)s, %(duration_ms)s, %(request_count)s, %(keepalive_used)s,
        %(mean_request_time_ms)s, %(p95_request_time_ms)s,
        %(max_request_time_ms)s, %(mean_inbound_byte_rate)s,
        %(partial_request_count)s, %(timeout_request_count)s, %(tls_version)s,
        %(tls_cipher)s
    )
    ON CONFLICT (id) DO UPDATE SET
        "tClose" = EXCLUDED."tClose",
        "durationMs" = EXCLUDED."durationMs",
        "requestCount" = EXCLUDED."requestCount",
        "meanRequestTimeMs" = EXCLUDED."meanRequestTimeMs",
        "p95RequestTimeMs" = EXCLUDED."p95RequestTimeMs",
        "maxRequestTimeMs" = EXCLUDED."maxRequestTimeMs",
        "meanInboundByteRate" = EXCLUDED."meanInboundByteRate",
        "partialRequestCount" = EXCLUDED."partialRequestCount",
        "timeoutRequestCount" = EXCLUDED."timeoutRequestCount"
    """
    with conn.cursor() as cur:
        execute_batch(cur, sql, upserts, page_size=50)
    conn.commit()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', default=LOG_PATH)
    parser.add_argument('--from-start', action='store_true',
                        help='Tail değil, dosyanın başından oku (one-shot)')
    args = parser.parse_args()

    db = psycopg2.connect(**DB_CONFIG)
    print(f"[ingester] connected to {DB_CONFIG['host']}:{DB_CONFIG['port']}")

    log_buffer = []
    last_flush = time.time()

    if args.from_start:
        print(f"[ingester] reading {args.log} from start (one-shot mode)")
        with open(args.log, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    log_buffer.append(entry)
                except json.JSONDecodeError:
                    continue
        print(f"[ingester] parsed {len(log_buffer)} lines")
        aggregate_connections(db, log_buffer)
        # update_connection_fields da yapılabilir; opsiyonel
        print("[ingester] done.")
        return

    print(f"[ingester] tailing {args.log}")
    for line in open_log(args.log):
        if not line:
            continue
        try:
            entry = json.loads(line)
            log_buffer.append(entry)
        except json.JSONDecodeError:
            continue

        now = time.time()
        if now - last_flush >= CONN_AGG_INTERVAL_SEC:
            print(f"[ingester] aggregating {len(log_buffer)} entries → Connection")
            aggregate_connections(db, log_buffer)
            log_buffer = []
            last_flush = now


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[ingester] stopped")
        sys.exit(0)
```

### 4.3 Ingester'ı çalıştır

Ayrı terminal:

```bash
cd /Users/beyzayavuz/Desktop/auth-nest-01/scripts
source venv/bin/activate
python ingest_nginx_log.py
```

Çıktıda `[ingester] connected to localhost:5432` ve `[ingester] tailing
.../ddos_research.log` görmelisin.

### 4.4 Smoke test — 1000 request, end-to-end

NestJS ve nginx çalışıyorken, ayrı terminalde:

```bash
# 200 request × 5 endpoint = 1000 hit
for i in {1..200}; do
  curl -s -H "x-simulation-label: e2e-test" http://localhost:8080/health > /dev/null
  curl -s -H "x-simulation-label: e2e-test" http://localhost:8080/ping > /dev/null
  curl -s -H "x-simulation-label: e2e-test" http://localhost:8080/metrics/users/count > /dev/null
  curl -s -H "x-simulation-label: e2e-test" "http://localhost:8080/metrics/reports/login-stats?hours=24" > /dev/null
  curl -s -H "x-simulation-label: e2e-test" http://localhost:8080/ > /dev/null
done

sleep 10

# 1) RequestLog satır sayısı
docker compose exec postgres psql -U research -d ddos_research -c "
SELECT count(*) AS request_log_count
FROM \"RequestLog\"
WHERE \"trafficLabel\"='e2e-test';"

# 2) Connection tablosu — ingester aggregate ettiyse satır olmalı
docker compose exec postgres psql -U research -d ddos_research -c "
SELECT count(*) AS connection_count, sum(\"requestCount\") AS total_requests
FROM \"Connection\";"

# 3) Sample row — bütün alanlar dolu mu?
docker compose exec postgres psql -U research -d ddos_research -c "
SELECT \"routeTemplate\", \"dbQueryCount\", \"cpuTimeMs\", \"uaFamily\",
       \"ipSubnet24\", \"connId\", \"sessionIdHash\", \"loginPresent\",
       \"acceptSetHash\"
FROM \"RequestLog\"
WHERE \"trafficLabel\"='e2e-test'
ORDER BY timestamp DESC LIMIT 3;"
```

**Beklenen:**
- `request_log_count` ≈ 1000 (LogsService batch flush 5s'de bir, biraz toleranslı)
- `connection_count` < 1000 (her request kendi connection'ı değil; nginx
  keep-alive ile bazı bağlantılar reuse oluyor)
- Sample row'da `dbQueryCount` (metrics endpoint'leri için >0), `cpuTimeMs > 0`,
  `uaFamily=curl`, `ipSubnet24=192.168.65.0/24`, `connId` dolu

Eğer Connection tablosu boşsa: ingester son 30 saniyede flush yapmamış demektir,
biraz daha bekle ve tekrar sorgula.

### Day 4 — Common errors

**E1: ingester `psycopg2.OperationalError: connection failed`**

Postgres çalışmıyor olabilir. `docker compose ps` ile kontrol et, gerekirse
`docker compose up -d postgres`.

**E2: Connection tablosu boş kalıyor.**

İngester aggregate eden `aggregate_connections` fonksiyonunda log_buffer dolu
olmayabilir. `from-start` mode ile one-shot çalıştırarak debug et:

```bash
python ingest_nginx_log.py --from-start
```

**E3: `INSERT INTO "Connection"` hatası: invalid CIDR value.**

`ipSubnet24` text olarak değil, postgres `inet` tipinde bekleniyor. Schema'da
`ip` field'ı `INET`, `ipSubnet24` ise text. Script'teki cast'i kontrol et.

### Day 4 commit

```bash
git add -A
git commit -m "Day 4 complete: nginx log ingester + Connection table populator"
```

---

## DAY 5 — NASA HTTP Log: Download, Parse, Distribution Fit

**Hedef:** Sentetik trafik üreten k6 script'lerinin parametrelerini gerçek
veriyle anchorla. NASA 1995 Jul/Aug HTTP logs en klasik public dataset.

### 5.1 Download

```bash
mkdir -p data/nasa
cd data/nasa

# Public NASA HTTP logs (1995 Jul/Aug)
curl -O https://ita.ee.lbl.gov/traces/NASA_access_log_Jul95.gz
curl -O https://ita.ee.lbl.gov/traces/NASA_access_log_Aug95.gz

# Decompress
gunzip NASA_access_log_Jul95.gz
gunzip NASA_access_log_Aug95.gz

# Boyut kontrolü
ls -lh
# Beklenen: Jul ~205MB, Aug ~167MB
```

### 5.2 Parser script

`scripts/parse_nasa.py`:

```python
"""
NASA HTTP log → DataFrame parse.
Format: 'host - - [date:time tz] "METHOD path HTTP/V" status bytes'
"""

import re
import pandas as pd
from datetime import datetime
from pathlib import Path
import argparse

LOG_RE = re.compile(
    r'^(\S+) - - \[([^\]]+)\] "([A-Z]+) (\S+) HTTP/([0-9.]+)" (\d+) (\S+)'
)


def parse_log(path):
    rows = []
    with open(path, 'r', encoding='latin-1') as f:
        for line in f:
            m = LOG_RE.match(line)
            if not m:
                continue
            host, ts, method, uri, http_v, status, size = m.groups()
            try:
                t = datetime.strptime(ts.split(' ')[0], '%d/%b/%Y:%H:%M:%S')
            except ValueError:
                continue
            rows.append({
                'host': host,
                'timestamp': t,
                'method': method,
                'uri': uri,
                'status': int(status),
                'size': int(size) if size != '-' else 0,
            })
    return pd.DataFrame(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True,
                        help='NASA log file path')
    parser.add_argument('--output', required=True,
                        help='Parsed CSV output path')
    args = parser.parse_args()

    print(f"[parse_nasa] reading {args.input}")
    df = parse_log(args.input)
    print(f"[parse_nasa] parsed {len(df)} rows")
    df.to_csv(args.output, index=False)
    print(f"[parse_nasa] saved to {args.output}")


if __name__ == '__main__':
    main()
```

Çalıştır:

```bash
cd scripts
source venv/bin/activate

python parse_nasa.py --input ../data/nasa/NASA_access_log_Jul95 \
                     --output ../data/nasa/nasa_jul95.csv
# Çıktı: parsed ~1.8M rows
```

### 5.3 Per-session segmentation + IAT distribution fit

`scripts/fit_nasa_distributions.py`:

```python
"""
NASA log üstünden:
- Per-host session segmentation (think-time threshold = 30 min)
- Inter-arrival time (IAT) within session
- Session length, request-per-session
- Endpoint popularity (Zipf)
- Lognormal/Weibull fit + KS test
- Sonuçları JSON olarak CalibrationBaseline tablosuna yazar
"""

import pandas as pd
import numpy as np
from scipy import stats
import json
import argparse
import psycopg2
from datetime import timedelta

DB_CONFIG = {
    'host': 'localhost', 'port': 5432, 'user': 'research',
    'password': 'research', 'dbname': 'ddos_research',
}
SESSION_GAP_SEC = 30 * 60  # 30 dakika gap = yeni session


def segment_sessions(df):
    """Her host için ardışık request'leri session'a böl."""
    df = df.sort_values(['host', 'timestamp']).reset_index(drop=True)
    df['gap_sec'] = df.groupby('host')['timestamp'].diff().dt.total_seconds()
    df['new_session'] = (df['gap_sec'].isna()) | (df['gap_sec'] > SESSION_GAP_SEC)
    df['session_id'] = df.groupby('host')['new_session'].cumsum()
    return df


def fit_iat(df):
    """Within-session IAT seconds — lognormal fit + KS test."""
    intra = df[~df['new_session']]['gap_sec'].dropna()
    intra = intra[(intra > 0) & (intra < SESSION_GAP_SEC)]

    log_iat = np.log(intra.values)
    mu = float(np.mean(log_iat))
    sigma = float(np.std(log_iat))

    # KS test against fitted lognormal
    ks_stat, ks_p = stats.kstest(
        intra.values,
        lambda x: stats.lognorm.cdf(x, sigma, scale=np.exp(mu)),
    )

    return {
        'distribution': 'lognormal',
        'log_mean': mu,
        'log_sigma': sigma,
        'sample_size': len(intra),
        'ks_statistic': float(ks_stat),
        'ks_pvalue': float(ks_p),
        'percentiles': {
            'p50': float(np.percentile(intra, 50)),
            'p75': float(np.percentile(intra, 75)),
            'p95': float(np.percentile(intra, 95)),
            'p99': float(np.percentile(intra, 99)),
        },
    }


def fit_session_length(df):
    """Session başına request sayısı — geometric tail fit."""
    sess = df.groupby(['host', 'session_id']).size()
    return {
        'distribution': 'empirical',
        'mean': float(sess.mean()),
        'median': float(sess.median()),
        'p95': float(sess.quantile(0.95)),
        'bounce_rate': float((sess == 1).sum() / len(sess)),
        'sample_size': len(sess),
    }


def fit_endpoint_zipf(df):
    """Endpoint popularity → Zipf alpha estimation."""
    counts = df['uri'].value_counts()
    ranks = np.arange(1, len(counts) + 1)
    log_rank = np.log(ranks)
    log_freq = np.log(counts.values)

    # Linear fit log-log
    slope, intercept, r, p, se = stats.linregress(log_rank, log_freq)
    alpha = -slope

    return {
        'distribution': 'zipf',
        'alpha': float(alpha),
        'r_squared': float(r ** 2),
        'unique_endpoints': len(counts),
        'top10': counts.head(10).to_dict(),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    parser.add_argument('--write-db', action='store_true',
                        help='CalibrationBaseline tablosuna yaz')
    args = parser.parse_args()

    print(f"[fit] loading {args.input}")
    df = pd.read_csv(args.input, parse_dates=['timestamp'])
    print(f"[fit] {len(df)} rows")

    # Filter: only successful GET
    df = df[(df['method'] == 'GET') & (df['status'].between(200, 299))]
    print(f"[fit] after filter: {len(df)} rows")

    df = segment_sessions(df)
    print(f"[fit] sessions: {df.groupby(['host','session_id']).ngroups}")

    iat_fit = fit_iat(df)
    sess_fit = fit_session_length(df)
    zipf_fit = fit_endpoint_zipf(df)

    print("\n=== IAT (within-session) ===")
    print(json.dumps(iat_fit, indent=2))

    print("\n=== Session length ===")
    print(json.dumps(sess_fit, indent=2))

    print("\n=== Endpoint Zipf ===")
    print(json.dumps(
        {k: v for k, v in zipf_fit.items() if k != 'top10'},
        indent=2,
    ))

    if args.write_db:
        db = psycopg2.connect(**DB_CONFIG)
        with db.cursor() as cur:
            for name, data in [
                ('nasa_iat_within_session', iat_fit),
                ('nasa_session_length', sess_fit),
                ('nasa_endpoint_zipf', zipf_fit),
            ]:
                cur.execute("""
                    INSERT INTO "CalibrationBaseline"
                    (name, "sourceDataset", parameters, "fitQuality")
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (name) DO UPDATE SET
                        parameters = EXCLUDED.parameters,
                        "fitQuality" = EXCLUDED."fitQuality"
                """, (
                    name,
                    'NASA_HTTP_1995',
                    json.dumps(data),
                    json.dumps({
                        'ks_statistic': data.get('ks_statistic'),
                        'ks_pvalue': data.get('ks_pvalue'),
                        'r_squared': data.get('r_squared'),
                    }),
                ))
        db.commit()
        print("\n[fit] saved to CalibrationBaseline")


if __name__ == '__main__':
    main()
```

Çalıştır:

```bash
cd scripts
source venv/bin/activate
pip install scipy

python fit_nasa_distributions.py \
  --input ../data/nasa/nasa_jul95.csv \
  --write-db
```

Beklenen çıktı (yaklaşık):
```
=== IAT (within-session) ===
{
  "log_mean": 1.2-1.8,
  "log_sigma": 0.7-1.0,
  ...
}
=== Endpoint Zipf ===
{
  "alpha": 0.95-1.20,
  "r_squared": 0.92-0.97
}
```

KS p-value muhtemelen küçük olacak (büyük sample size'da). Asıl baktığımız
**parametre tahmini** ve **R² fit kalitesi**.

### 5.4 Sanity: Calibration baseline DB'de mi?

```bash
docker compose exec postgres psql -U research -d ddos_research -c "
SELECT name, \"sourceDataset\", \"createdAt\"
FROM \"CalibrationBaseline\"
ORDER BY \"createdAt\" DESC;"
```

Üç satır görmelisin: nasa_iat_within_session, nasa_session_length,
nasa_endpoint_zipf.

### Day 5 commit

```bash
git add -A
git commit -m "Day 5 complete: NASA log download, parse, distribution fits"
```

---

## DAY 6 — Markov Chain + Endpoint Mapping + IAT Empirical CDF

**Hedef:** NASA-derived endpoint transition matrix oluştur, test app'inin
endpoint'lerini NASA kategorilerine map et, IAT empirical CDF'ini sakla
(inverse-transform sampling için Day 8'e hazır).

### 6.1 Endpoint kategorizasyonu (NASA → 4 sınıf)

`scripts/build_markov_matrix.py`:

```python
"""
NASA log endpoint'lerini 4 kategoriye ayır:
- HTML page (e.g., /shuttle/missions/sts-71/news.html)
- Image (e.g., /images/foo.gif, /shuttle/foo.jpg)
- Static asset (e.g., .css, .js)
- API/dynamic (e.g., /cgi-bin/, /htbin/)

Sonra her kategori arası transition matrix'i çıkar.
Markov state = endpoint kategorisi.
"""

import pandas as pd
import numpy as np
import json
import argparse
import psycopg2
from urllib.parse import urlparse

DB_CONFIG = {
    'host': 'localhost', 'port': 5432, 'user': 'research',
    'password': 'research', 'dbname': 'ddos_research',
}


def categorize(uri):
    path = uri.lower()
    if path.endswith(('.html', '.htm', '/')):
        return 'html'
    if path.endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg')):
        return 'image'
    if path.endswith(('.css', '.js')):
        return 'static_asset'
    if '/cgi-bin/' in path or '/htbin/' in path or path.endswith('.cgi'):
        return 'api_dynamic'
    if path.endswith(('.txt', '.pdf', '.zip', '.tar')):
        return 'static_asset'
    return 'other'


def build_matrix(df):
    df = df.sort_values(['host', 'timestamp']).reset_index(drop=True)
    df['category'] = df['uri'].apply(categorize)

    # Per-session transitions
    df['gap_sec'] = df.groupby('host')['timestamp'].diff().dt.total_seconds()
    df['new_session'] = (df['gap_sec'].isna()) | (df['gap_sec'] > 30 * 60)
    df['session_id'] = df.groupby('host')['new_session'].cumsum()

    # Within-session transitions
    df['next_category'] = df.groupby(['host', 'session_id'])['category'].shift(-1)
    df['next_category'] = df['next_category'].fillna('exit')

    # Add 'start' state for first request of each session
    transitions = []
    for (host, sid), grp in df.groupby(['host', 'session_id']):
        prev = 'start'
        for _, row in grp.iterrows():
            transitions.append({'from': prev, 'to': row['category']})
            prev = row['category']
        transitions.append({'from': prev, 'to': 'exit'})

    tdf = pd.DataFrame(transitions)
    matrix = pd.crosstab(tdf['from'], tdf['to'], normalize='index')

    return matrix.to_dict(), df['category'].value_counts().to_dict()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    parser.add_argument('--write-db', action='store_true')
    args = parser.parse_args()

    df = pd.read_csv(args.input, parse_dates=['timestamp'])
    df = df[(df['method'] == 'GET') & (df['status'].between(200, 299))]

    matrix, category_counts = build_matrix(df)

    print("=== Markov transition matrix ===")
    print(json.dumps(matrix, indent=2))

    print("\n=== Category counts ===")
    print(json.dumps(category_counts, indent=2))

    if args.write_db:
        db = psycopg2.connect(**DB_CONFIG)
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO "CalibrationBaseline"
                (name, "sourceDataset", parameters, "fitQuality")
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (name) DO UPDATE SET
                    parameters = EXCLUDED.parameters,
                    "fitQuality" = EXCLUDED."fitQuality"
            """, (
                'nasa_markov_endpoint',
                'NASA_HTTP_1995',
                json.dumps({
                    'states': ['start', 'html', 'image', 'static_asset',
                               'api_dynamic', 'other', 'exit'],
                    'matrix': matrix,
                    'category_counts': category_counts,
                }),
                json.dumps({'sample_size': len(df)}),
            ))
        db.commit()
        print("[markov] saved to CalibrationBaseline")


if __name__ == '__main__':
    main()
```

Çalıştır:

```bash
python build_markov_matrix.py \
  --input ../data/nasa/nasa_jul95.csv \
  --write-db
```

### 6.2 Test app endpoint'lerini NASA kategorisine map

Yeni dosya: `scripts/endpoint_mapping.json`

```json
{
  "/": "html",
  "/health": "api_dynamic",
  "/ping": "api_dynamic",
  "/auth/login": "api_dynamic",
  "/auth/register": "api_dynamic",
  "/auth/logout": "api_dynamic",
  "/auth/refresh-token": "api_dynamic",
  "/user/profile": "api_dynamic",
  "/user/update": "api_dynamic",
  "/user/change-password": "api_dynamic",
  "/user/delete": "api_dynamic",
  "/user/search": "api_dynamic",
  "/metrics/users/count": "api_dynamic",
  "/metrics/reports/login-stats": "api_dynamic"
}
```

> **Not:** Senin test app'in çoğunlukla API endpoints. NASA web sitesinden farklı
> bir trafik karakteristiği var. Markov chain'i sadece "html / api_dynamic /
> exit" subset'ine indirgemen gerekecek Day 8'de. Bu mapping dosyası bir
> sonraki adıma referans.

### 6.3 IAT empirical CDF

`scripts/build_iat_cdf.py`:

```python
"""
NASA IAT'ları için empirical CDF tablo halinde sakla.
Inverse transform sampling: P(X<=x) verilince x'i döndüren tablo.
"""

import pandas as pd
import numpy as np
import json
import argparse
import psycopg2

DB_CONFIG = {
    'host': 'localhost', 'port': 5432, 'user': 'research',
    'password': 'research', 'dbname': 'ddos_research',
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    parser.add_argument('--bins', type=int, default=200)
    args = parser.parse_args()

    df = pd.read_csv(args.input, parse_dates=['timestamp'])
    df = df.sort_values(['host', 'timestamp']).reset_index(drop=True)
    df['gap_sec'] = df.groupby('host')['timestamp'].diff().dt.total_seconds()
    iat = df[(df['gap_sec'] > 0) & (df['gap_sec'] < 1800)]['gap_sec'].values

    # Quantile-based CDF table
    quantiles = np.linspace(0, 1, args.bins)
    values = np.quantile(iat, quantiles)

    cdf_table = list(zip(quantiles.tolist(), values.tolist()))

    db = psycopg2.connect(**DB_CONFIG)
    with db.cursor() as cur:
        cur.execute("""
            INSERT INTO "CalibrationBaseline"
            (name, "sourceDataset", parameters, "fitQuality")
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (name) DO UPDATE SET
                parameters = EXCLUDED.parameters
        """, (
            'nasa_iat_empirical_cdf',
            'NASA_HTTP_1995',
            json.dumps({'cdf_table': cdf_table, 'sample_size': len(iat)}),
            json.dumps({}),
        ))
    db.commit()
    print(f"[iat-cdf] saved {args.bins}-bin CDF, n={len(iat)}")


if __name__ == '__main__':
    main()
```

Çalıştır:

```bash
python build_iat_cdf.py --input ../data/nasa/nasa_jul95.csv
```

### 6.4 Sanity

```bash
docker compose exec postgres psql -U research -d ddos_research -c "
SELECT name, \"sourceDataset\",
       jsonb_object_keys(parameters) AS keys
FROM \"CalibrationBaseline\"
ORDER BY name;"
```

5 baseline görmelisin: nasa_iat_within_session, nasa_session_length,
nasa_endpoint_zipf, nasa_markov_endpoint, nasa_iat_empirical_cdf.

### Day 6 commit

```bash
git add -A
git commit -m "Day 6 complete: NASA Markov matrix + endpoint mapping + IAT empirical CDF"
```

---

## DAY 7 — Week 1 Final Checkpoint

**Hedef:** Her şey end-to-end çalışıyor mu, calibration data integrity sağlam mı,
tezdeki methodology'nin temel cümlelerini taslak olarak yaz.

### 7.1 End-to-end smoke test

```bash
# NestJS, nginx, postgres, ingester hepsi çalışıyor mu?
docker compose ps
ps aux | grep "ingest_nginx_log" | grep -v grep
ps aux | grep "nest start" | grep -v grep

# 50 request × 4 endpoint
for i in {1..50}; do
  curl -s -H "x-simulation-label: week1-final" http://localhost:8080/health > /dev/null
  curl -s -H "x-simulation-label: week1-final" http://localhost:8080/metrics/users/count > /dev/null
  curl -s -H "x-simulation-label: week1-final" "http://localhost:8080/metrics/reports/login-stats?hours=24" > /dev/null
  curl -s -H "x-simulation-label: week1-final" http://localhost:8080/ping > /dev/null
done

sleep 15

# RequestLog: tüm yeni alanlar dolu mu?
docker compose exec postgres psql -U research -d ddos_research -c "
SELECT
  count(*) AS total,
  count(\"dbQueryCount\") FILTER (WHERE \"dbQueryCount\" > 0) AS with_db_metric,
  count(\"cpuTimeMs\") FILTER (WHERE \"cpuTimeMs\" > 0) AS with_cpu_metric,
  count(\"uaFamily\") FILTER (WHERE \"uaFamily\" IS NOT NULL) AS with_ua_family,
  count(\"ipSubnet24\") FILTER (WHERE \"ipSubnet24\" IS NOT NULL) AS with_ip_subnet,
  count(\"connId\") FILTER (WHERE \"connId\" IS NOT NULL) AS with_conn_id
FROM \"RequestLog\"
WHERE \"trafficLabel\"='week1-final';"

# Connection: aggregate edildi mi?
docker compose exec postgres psql -U research -d ddos_research -c "
SELECT
  count(*) AS connections,
  avg(\"requestCount\") AS avg_req_per_conn,
  avg(\"meanRequestTimeMs\") AS avg_req_time
FROM \"Connection\"
WHERE \"tOpen\" >= now() - interval '5 minutes';"

# CalibrationBaseline: 5 baseline var mı?
docker compose exec postgres psql -U research -d ddos_research -c "
SELECT count(*) AS baselines FROM \"CalibrationBaseline\";"
```

**Beklenen:**
- `total = 200`
- `with_db_metric` ≈ 100 (sadece /metrics/* DB hit ediyor)
- `with_cpu_metric = 200` (tüm endpoint'ler CPU harcadı)
- `with_ua_family = 200`
- `with_ip_subnet = 200`
- `with_conn_id` = 200 (ya da çok yakın — ingester gecikmesi olabilir)
- `connections` > 0 (genelde curl her seferinde yeni connection açar, ama keep-alive
  varsa daha az)
- `baselines = 5`

Bu hepsi geçerse **Week 1 tamam** demektir.

### 7.2 Methodology taslak — şimdi yaz, sonra unutma

Yeni dosya: `docs/methodology_draft.md`. Aşağıdaki başlıklar için 2-3 cümlelik
taslak yaz (tezde Methodology bölümünün ham malzemesi):

```markdown
# Methodology — Draft

## System Architecture
Test bed: NestJS application (Node.js, Prisma ORM) behind nginx reverse proxy,
backed by local PostgreSQL 16. Both nginx and PostgreSQL run in Docker
containers; NestJS runs natively on host for hot-reload during development.
Production deployment uses managed cloud PostgreSQL (Aiven), but for
controlled experiments we use a local instance to eliminate network latency
variance from backend cost measurements.

## Instrumentation
Every HTTP request is instrumented at three layers:
- nginx access log captures connection-level data ($connection,
  $connection_requests, $request_time, $upstream_*_time, $bytes_received)
  in JSON format.
- A NestJS interceptor (BackendCostInterceptor) measures backend cost via
  process.cpuUsage() and Prisma's $on('query') event hook, propagated
  through async hops via AsyncLocalStorage. Backend cost is exported as
  custom response headers (X-DB-Query-Count, X-CPU-Time-Ms, etc.) which
  nginx logs via $sent_http_x_*.
- Existing RequestLoggerMiddleware aggregates HTTP-level features
  (User-Agent family via ua-parser-js, IP /24 subnet, header presence
  flags, session id hash from JWT subject) and writes a unified record to
  the RequestLog Postgres table.

## Threat Model
Rate-limiting, IP blocking, and account lockout infrastructure exist in the
application (IpBlock model, lockedUntil column) but are deliberately disabled
during behavioral measurement experiments. This isolates the behavioral
detection signal from rate-limit-induced traffic distortions. Detection vs.
rate-limiting comparison is left for future work.

## Calibration
Behavioral baselines are derived from the NASA HTTP server access logs
(July 1995, ~1.8M requests, 80K unique hosts). Inter-arrival time within
sessions is fitted to a lognormal distribution; session length follows a
geometric tail with high bounce rate; endpoint popularity follows a Zipf
distribution with α ≈ 1.0. A per-session Markov transition matrix over
endpoint categories (HTML, image, static asset, API) is extracted for
sequential behavior modeling.

## Limitations
- Synthetic-only validation (single application, controlled environment)
- IPv4-only IP analysis
- TLS fingerprinting (JA3/JA4) deferred to future work
- Iterative adaptive adversary not tested; one-shot mimicry test included
- TypeScript ORM coverage of Prisma instrumentation is approximately
  complete but raw SQL queries via $queryRaw may bypass the hook
```

Bu taslağı tezi yazarken genişleteceksin. Şimdi yazmamak ileride %50 unutmuş
olarak yazmak demek.

### 7.3 Git commit + tag

```bash
git add -A
git commit -m "Day 7: Week 1 final checkpoint, methodology draft, calibration baselines verified"

# Week 1'i tag'le
git tag -a week-1-complete -m "Week 1: architecture, instrumentation, NASA calibration"
git push origin week-1-complete
```

### 7.4 Week 2'ye hazırlık

Week 2'de k6 refactor sprint'i başlıyor (`docs/traffic_scripts_critique.md`'deki
P0/P1 düzeltmeleri). Day 8 sabahı şu sırayla başla:

1. `docs/traffic_scripts_critique.md`'i tekrar oku (k6 sprint'in haritası)
2. `project_plan_4weeks.md` Week 2'yi oku
3. `k6-common/` dizini oluştur
4. `k6-traffics.js`'in legitimate flow'unu common modüle taşı

Day 8 için detaylı kod tariflerini ayrıca yazacağız (DAYS_8_TO_14.md), ama
bu hafta sonu Week 1'i tamamla, dinlen, Week 2'ye taze gir.

---

## Genel Hatırlatma

- Her gün sonunda **commit** yap. Çalışan halini snapshot'la.
- Bug yaşarsan o gün için scope cut yap, plan'a sadık kal.
- Methodology'yi haftalık güncel tut. Tezde son haftaya yığma.
- Aiven şifresini hâlâ rotate etmediysen **bu hafta yap**.

İyi şanslar.
