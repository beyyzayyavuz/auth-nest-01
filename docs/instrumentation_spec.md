# NestJS Instrumentation Spec — Week 1 Day 2–3

## Amaç

NestJS uygulamasının her request için şu bilgileri **response header** olarak nginx'e
geri döndürmesi:

- `X-Route-Template` — matched route template (örn. `/users/:id`)
- `X-DB-Query-Count` — bu request sırasında çalıştırılan DB query sayısı
- `X-DB-Total-Time-Ms` — DB query'lerinin toplam süresi
- `X-CPU-Time-Ms` — handler içinde geçen CPU time
- `X-External-Call-Count` — outbound HTTP/RPC çağrıları sayısı
- `X-Session-Id-Hash` — session id'nin sha256 ilk 16 byte'ı (varsa)
- `X-Login-Present` — kullanıcı login mi (`0`/`1`)
- `X-T-Recv` — `process.hrtime` ile request handler'a giriş anı
- `X-T-Handler-Start`, `X-T-Handler-End` — handler içi timing

Bu header'lar nginx tarafından access log'a yazılıyor ve `proxy_hide_header` ile
client'tan gizleniyor (önceki nginx config dosyasına bak).

---

## 1. Endpoint Katalogu — minimum diversity

Test app'inde aşağıdaki endpoint sınıfları **mutlaka** olmalı. Behavioral
discrimination'ın gerçekçi davranabilmesi için endpoint cost diversity zorunlu.

| Route | Method | Cost class | Açıklama | Auth gerekli? |
|---|---|---|---|---|
| `/health` | GET | cheap | Static "OK" cevabı, DB yok | Hayır |
| `/ping` | GET | cheap | Aynı, secondary endpoint | Hayır |
| `/products` | GET | medium | DB read (~100 row paginate) | Hayır |
| `/products/:id` | GET | medium | DB read tek row + 1-2 join | Hayır |
| `/search` | GET (query=`q=`) | very expensive | LIKE/full-text query, aggregate | Hayır |
| `/reports/summary` | GET | expensive | Multi-table aggregate | Evet (auth) |
| `/comments` | POST | medium-write | Insert + validation | Evet (auth) |
| `/auth/login` | POST | medium | Password hash compare + cookie set | Hayır (login flow) |
| `/auth/logout` | POST | cheap | Cookie clear | Evet |
| `/me` | GET | cheap-auth | Session lookup, no DB | Evet |

**Minimum 4 cost quartile** dolu olmalı (cheap, medium, expensive, very expensive). Aksi
halde `endpoint_cost_sum` feature'ı yapay olarak az varyans gösterir, modelin bu
boyuttan bilgi çıkaramaz.

**Notlar:**
- `/search` için intentional olarak yavaş (LIKE'lı, index'siz) bir SQL kur. Adversary
  asymmetric resource exhaustion senaryosu için bu endpoint en kritik.
- `/auth/login` rate-limit ETME (research için). Production'da olmaz, biz davranışı
  ölçüyoruz.
- Login flow zorunlu — Tier 4 session feature'ları tutmaya karar verdik.

---

## 2. Global Interceptor — Backend Cost Capture

NestJS'de tek bir `BackendCostInterceptor` her request'i sarmalıyor.

```typescript
// src/common/interceptors/backend-cost.interceptor.ts
import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { performance } from 'perf_hooks';
import { createHash } from 'crypto';
import { AsyncLocalStorage } from 'async_hooks';

// AsyncLocalStorage ile her request için izole counter'lar
export interface RequestMetrics {
  dbQueryCount: number;
  dbTotalTimeMs: number;
  externalCallCount: number;
  tRecv: number;        // ms epoch
  tHandlerStart: number;
  tHandlerEnd: number;
}

export const requestMetricsStorage = new AsyncLocalStorage<RequestMetrics>();

@Injectable()
export class BackendCostInterceptor implements NestInterceptor {
  intercept(ctx: ExecutionContext, next: CallHandler): Observable<any> {
    const httpCtx = ctx.switchToHttp();
    const req = httpCtx.getRequest();
    const res = httpCtx.getResponse();

    // tRecv: nginx'in X-Recv-Start header'ından gelir
    const tRecvHeader = req.headers['x-recv-start'];
    const tRecv = tRecvHeader ? parseFloat(tRecvHeader) * 1000 : Date.now();

    const metrics: RequestMetrics = {
      dbQueryCount: 0,
      dbTotalTimeMs: 0,
      externalCallCount: 0,
      tRecv,
      tHandlerStart: performance.now(),
      tHandlerEnd: 0,
    };

    return requestMetricsStorage.run(metrics, () => {
      const cpuStart = process.cpuUsage();
      return next.handle().pipe(
        tap({
          next: () => this.writeHeaders(req, res, metrics, cpuStart),
          error: () => this.writeHeaders(req, res, metrics, cpuStart),
        }),
      );
    });
  }

  private writeHeaders(req, res, m: RequestMetrics, cpuStart) {
    m.tHandlerEnd = performance.now();
    const cpuDiff = process.cpuUsage(cpuStart);
    const cpuTimeMs = (cpuDiff.user + cpuDiff.system) / 1000;

    // route template: NestJS Reflector ile route handler metadata'sından
    // alınabilir; basit yol req.route?.path
    const routeTemplate = req.route?.path || 'unknown';

    // session
    const sessionId = req.session?.id;
    const sessionIdHash = sessionId
      ? createHash('sha256').update(sessionId).digest('hex').slice(0, 32)
      : '';
    const loginPresent = req.session?.userId ? '1' : '0';

    res.setHeader('X-Route-Template', routeTemplate);
    res.setHeader('X-DB-Query-Count', String(m.dbQueryCount));
    res.setHeader('X-DB-Total-Time-Ms', m.dbTotalTimeMs.toFixed(2));
    res.setHeader('X-CPU-Time-Ms', cpuTimeMs.toFixed(2));
    res.setHeader('X-External-Call-Count', String(m.externalCallCount));
    res.setHeader('X-Session-Id-Hash', sessionIdHash);
    res.setHeader('X-Login-Present', loginPresent);
    res.setHeader('X-T-Recv', String(m.tRecv));
    res.setHeader('X-T-Handler-Start', m.tHandlerStart.toFixed(3));
    res.setHeader('X-T-Handler-End', m.tHandlerEnd.toFixed(3));
  }
}
```

**Register** `app.useGlobalInterceptors(new BackendCostInterceptor())` `main.ts`'de.

---

## 3. TypeORM Hook — DB Query Counter

DB sorgu sayısı ve süresi için TypeORM logger interface'ini kullan.

```typescript
// src/common/db/metric-logger.ts
import { Logger as TypeOrmLogger, QueryRunner } from 'typeorm';
import { performance } from 'perf_hooks';
import { requestMetricsStorage } from '../interceptors/backend-cost.interceptor';

export class MetricCollectingLogger implements TypeOrmLogger {
  logQuery(query: string, parameters?: any[], queryRunner?: QueryRunner) {
    const m = requestMetricsStorage.getStore();
    if (!m) return;
    // query başlangıcını runner üzerine işaretle
    (queryRunner as any)._queryStartTime = performance.now();
  }

  logQueryError() { /* ... */ }
  logQuerySlow() { /* ... */ }
  logSchemaBuild() { /* ... */ }
  logMigration() { /* ... */ }
  log() { /* ... */ }

  // TypeORM doesn't have native logQueryEnd in standard interface;
  // alternatif: Subscriber or custom datasource wrapper kullan.
}
```

**Daha temiz alternatif:** TypeORM `DataSource` üstüne wrapper koy ve `query()`
metodunu intercept et. Veya `QueryRunner` event'leri (`afterQuery` yok ama subscriber
pattern var). En basit, en güvenli yol:

```typescript
// src/common/db/instrumented-datasource.ts
import { DataSource, QueryRunner } from 'typeorm';
import { performance } from 'perf_hooks';
import { requestMetricsStorage } from '../interceptors/backend-cost.interceptor';

export function instrumentDataSource(ds: DataSource): DataSource {
  const original = ds.query.bind(ds);
  ds.query = async function (sql: string, params?: any[]) {
    const m = requestMetricsStorage.getStore();
    const t0 = performance.now();
    try {
      return await original(sql, params);
    } finally {
      const dt = performance.now() - t0;
      if (m) {
        m.dbQueryCount += 1;
        m.dbTotalTimeMs += dt;
      }
    }
  };
  return ds;
}
```

Repository pattern'de TypeORM internal'da kendi query'lerini çalıştırdığı için bu
yaklaşım her query'i yakalamaz. **Daha güvenilir yol:** TypeORM `Subscriber` veya
`afterLoad/beforeQuery` lifecycle, veya postgres-level statement timing
(`pg_stat_statements`) cross-reference.

**v1 öneri:** Her endpoint'te `EntityManager` veya `DataSource.query()` doğrudan
kullan, repository pattern'i bypass et — research test app olduğu için kabul edilebilir.
Bu kısıtı `instrumentation_spec.md`'in "limitations" bölümüne yaz.

---

## 4. External Call Counter

`HttpService` veya `axios` çağrısı yapan her yerde counter increment et:

```typescript
import { HttpService } from '@nestjs/axios';
import { requestMetricsStorage } from '../interceptors/backend-cost.interceptor';

// HttpService wrapper veya axios interceptor
axios.interceptors.request.use((cfg) => {
  const m = requestMetricsStorage.getStore();
  if (m) m.externalCallCount += 1;
  return cfg;
});
```

v1'de external API call yok büyük ihtimalle; bu counter 0 kalacak. Ama infrastructure
hazır olsun.

---

## 5. Session Setup

`express-session` veya `@nestjs/session` kullanımı:

```typescript
// main.ts
import * as session from 'express-session';
app.use(session({
  secret: process.env.SESSION_SECRET || 'research-only-secret',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 30 * 60 * 1000, httpOnly: true, sameSite: 'lax' },
}));
```

`req.session.id` her zaman exist eder (saveUninitialized: true). Login flow'da
`req.session.userId = user.id` set edilir; logout'ta `req.session.destroy()`.

---

## 6. Response Header Hijack Koruması

Test app'inde herhangi bir custom header set eden kullanıcı endpoint'i, bizim
`X-*` header'larımızı override etmesin. Interceptor `next.handle()` SONRASINDA
header'ları yazıyor (yukarıdaki kodda `tap` içinde) — bu sıralama korunmalı.

---

## 7. Log Path End-to-End

```
client request
    ↓
nginx
  ├─ access log fields (raw HTTP, timing, conn_id, etc.)
  └─ proxy_pass → NestJS
                    ↓
                  BackendCostInterceptor (start)
                    ↓
                  TypeORM instrumented (counter++)
                    ↓
                  handler logic
                    ↓
                  BackendCostInterceptor (end)
                    ├─ res.setHeader('X-DB-Query-Count', ...)
                    └─ res.setHeader('X-CPU-Time-Ms', ...)
                    ↓
                  response → nginx
                              ├─ access log: $sent_http_x_db_query_count vs.
                              └─ proxy_hide_header: client'a gitmez
                                  ↓
                                client response (header'sız)

nginx access log → ddos_research.log → tail/filebeat → PostgreSQL.requests
```

---

## 8. Sanity Tests — Day 4 sonunda

1. `curl localhost/health` → log'da `x_route_template = "/health"`,
   `x_db_query_count = "0"`, `x_cpu_time_ms < 5`.
2. `curl localhost/products` → `x_db_query_count >= 1`, `x_db_total_time_ms > 0`.
3. `curl localhost/search?q=test` → `x_db_query_count >= 1`, `x_db_total_time_ms`
   yüksek (LIKE pahalı).
4. Login flow: `POST /auth/login` → set-cookie var, sonraki `/me` çağrısında
   `x_session_id_hash` aynı, `x_login_present = "1"`.
5. PostgreSQL `requests` tablosuna 100 request'lik smoke trafiği akmış mı kontrol et.
6. `path_route` değerleri NULL/unknown DEĞİL — eğer öyleyse interceptor route
   metadata'sını doğru çekmiyor demektir, fix et.

Bu 6 sanity test geçmeden Day 5'e (calibration) geçme.

---

## 9. Limitations (tezde "Methodology" bölümünde yazılacak)

1. `header_recv_duration` ve `body_recv_duration`'ı saf NestJS-only setup'tan tam
   çıkaramayız; nginx'in `upstream_connect_time` ve `request_time` farkı bir
   approximation. Tier B (`http.Server` low-level instrumentation) v1'de yok.
2. TypeORM repository pattern bazı internal query'leri kaçırabilir; `DataSource.query`
   wrapper coverage'ı %100 değil. Tezde belirt.
3. JA3/JA4 v1'de yok; bu, "TLS-fingerprint-based detection"a karşı behavioral
   detection'ın ne kadar bağımsız olduğunu doğrulayan bir ablation oluyor v2'de.
4. CPU time wall-clock değil process.cpuUsage farkı; multi-core'da bias yapabilir.
5. AsyncLocalStorage Node 14+'da stable, performance overhead düşük (~1-2 µs per
   request); ama yine de pure middleware'e göre ekstra cost.
