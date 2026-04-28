# START HERE — Week 1 implementation

Bu doküman Day 1 ve Day 2'yi adım adım yürütür. Her adımdan sonra **sanity test** var,
geçmeden bir sonraki adıma geçme. Day 3-4 için ayrı doküman gelecek.

> Tüm komutlar projenin kök dizininde (`/Users/beyzayavuz/Desktop/auth-nest-01`)
> çalıştırılır.

---

## DAY 1 — Infrastructure smoke test

### 1.1 Önkoşul: Docker Desktop

Docker Desktop kurulu mu?

```bash
docker --version
docker compose version
```

Yoksa: https://www.docker.com/products/docker-desktop/ → indir, kur, başlat.
Brew ile: `brew install --cask docker`

### 1.2 Postgres ve nginx'i başlat

```bash
mkdir -p infra/nginx/logs
docker compose up -d postgres nginx
```

Beklenen çıktı:
```
✔ Container ddos_postgres  Started
✔ Container ddos_nginx     Started
```

### 1.3 Sanity: containerlar yaşıyor mu?

```bash
docker compose ps
```

Her ikisi de `running`/`Up` olmalı. Eğer nginx restart loop'taysa:

```bash
docker compose logs nginx
```

En sık hata: `infra/nginx/nginx.conf` mount'u bulunmuyor — proje köküne `cd` ettiğinden
emin ol.

### 1.4 Postgres'e bağlanabiliyor musun?

```bash
docker compose exec postgres psql -U research -d ddos_research -c "SELECT version();"
```

PostgreSQL versiyon bilgisi dönmeli.

### 1.5 NestJS'i bu yeni Postgres'e bağla

Senin mevcut `.env` muhtemelen başka bir DB'ye bakıyor. Geçici olarak bu projeye özel
DB'ye yönlendir:

```bash
# .env dosyanı aç ve ekle/güncelle:
DATABASE_URL="postgresql://research:research@localhost:5432/ddos_research?schema=public"
JWT_SECRET="research-only-secret-change-in-prod"
ALLOW_TEST_IP_HEADER=true
```

> `ALLOW_TEST_IP_HEADER=true` önemli: Traffic generator'ların `x-test-client-ip` ile
> sahte IP gönderebilmesi için. Senin middleware'in bu flag'i okuyor zaten.

### 1.6 Mevcut Prisma migration'larını yeni DB'ye uygula

```bash
npx prisma migrate deploy
npx prisma generate
```

`migrate deploy` mevcut migration'ları çalıştırır, schema'yı kurar.

Sanity:
```bash
docker compose exec postgres psql -U research -d ddos_research -c "\dt"
```

`User`, `LoginAttempt`, `IpBlock`, `RequestLog`, `_prisma_migrations` tabloları
görünmeli.

### 1.7 NestJS'i başlat

Yeni terminal:
```bash
npm run start:dev
```

`Application is running on: http://localhost:3000` görmelisin.

### 1.8 nginx → NestJS smoke test

Üçüncü terminal:
```bash
# Doğrudan NestJS (port 3000)
curl -i http://localhost:3000/

# nginx üstünden (port 8080) — aynı cevabı vermeli
curl -i http://localhost:8080/
```

İkisi de `Hello World!` (veya AppService.getHello()'nun döndürdüğü) cevap vermeli.

### 1.9 nginx access log'u akıyor mu?

```bash
tail -f infra/nginx/logs/ddos_research.log
```

Yeni terminal:
```bash
curl http://localhost:8080/
```

Tail eden terminalde tek satır JSON görmeli:
```json
{"t_recv_start":"1714230000.123","request_time":"0.012","upstream_connect_time":"0.001",...}
```

**Eğer log boşsa:** nginx config syntax hatası vardır.
```bash
docker compose exec nginx nginx -t
docker compose restart nginx
```

### 1.10 NestJS'in yeni request'i Postgres'e yazdığını doğrula

```bash
# 5 request at, label'la
for i in {1..5}; do
  curl -s -H "x-simulation-label: smoke-test" http://localhost:8080/ > /dev/null
done

# 5 saniye bekle (LogsService 5s'de bir flush yapıyor)
sleep 6

# DB'de görelim
docker compose exec postgres psql -U research -d ddos_research \
  -c "SELECT method, \"routeTemplate\", \"statusCode\", \"trafficLabel\" FROM \"RequestLog\" ORDER BY timestamp DESC LIMIT 5;"
```

5 satır görmelisin, hepsi `trafficLabel=smoke-test`.

> **Çift kayıt sorunu:** nginx access log'u VE Prisma `RequestLog` aynı request'i
> yazıyor, çünkü iki ayrı log path'i var. Bu **kasten** öyle: nginx connection-level
> ve timing precision için, Prisma backend cost ve session info için. Day 4'te
> ikisini birleştireceğiz.

### 1.11 Day 1 bitti mi?

Checklist:
- [ ] `docker compose ps` → postgres + nginx Up
- [ ] `curl http://localhost:8080/` → 200 OK
- [ ] `infra/nginx/logs/ddos_research.log` → her curl bir JSON satırı yazıyor
- [ ] `RequestLog` tablosunda 5 smoke-test kaydı var

Hepsi tickliyse Day 2'ye geç. Tıklamıyorsa **devam etme**, neyin patladığını çöz.

---

## DAY 2 — Prisma schema extension + endpoint diversity

Bugün iki şey yapacağız:
1. `RequestLog` modelini behavioral feature kolonlarıyla genişlet
2. Yeni modelleri ekle: `Connection`, `BehavioralSession`, `WindowLabel`,
   `EndpointCostProfile`, `Scenario`, `CalibrationBaseline`
3. Cheap/medium/expensive endpoint diversity için 3 yeni endpoint ekle

### 2.1 Prisma schema'yı genişlet

`prisma/schema.prisma` dosyanı aç ve **mevcut `RequestLog`** modelini bununla
**değiştir** (eski alanları kaybetmiyoruz, üzerine ekliyoruz):

```prisma
model RequestLog {
  id              Int      @id @default(autoincrement())
  correlationId   String   @db.Uuid
  clientHash      String
  ip              String
  ipSubnet24      String?  // network(set_masklen(ip, 24)) — Day 3'te middleware doldurur
  userAgent       String
  uaFamily        String?  // Day 3: ua-parser-js ile türetilir
  uaRawHash       String?  // sha256(userAgent), cardinality için
  method          String
  routeTemplate   String
  url             String   @db.Text
  queryStrLen     Int      @default(0)
  bodyLenReceived Int      @default(0)
  statusCode      Int
  responseTimeMs  Float
  payloadSize     Int      @default(0)
  headerSize      Int
  headerCount     Int      @default(0)
  refererPresent  Boolean  @default(false)
  cookiePresent   Boolean  @default(false)
  acceptLangPresent Boolean @default(false)
  acceptEncPresent  Boolean @default(false)
  acceptSetHash   String?

  // Backend cost (Day 3: Prisma $on('query') hook + process.cpuUsage doldurur)
  dbQueryCount    Int      @default(0)
  dbTotalTimeMs   Float    @default(0)
  cpuTimeMs       Float    @default(0)
  externalCallCount Int    @default(0)

  // Connection (nginx'ten gelir, Day 4: log ingester doldurur)
  connId          String?
  connRequestIndex Int?

  // Session (Day 3: JWT subject veya clientHash fallback)
  sessionIdHash   String?
  loginPresent    Boolean  @default(false)

  // Partial request flag — slowloris signature
  partialRequest  Boolean  @default(false)

  trafficLabel    String   @default("unlabeled")
  scenarioId      String?
  timestamp       DateTime @default(now())

  @@index([clientHash])
  @@index([timestamp])
  @@index([ip, timestamp])
  @@index([ipSubnet24, timestamp])
  @@index([sessionIdHash, timestamp])
  @@index([scenarioId, timestamp])
  @@index([trafficLabel, timestamp])
}
```

Aynı dosyaya, `RequestLog`'un altına yeni modelleri ekle:

```prisma
model Scenario {
  id                String    @id
  name              String
  description       String?
  startedAt         DateTime
  endedAt           DateTime?
  legitimateWorkers Int?
  floodWorkers      Int?
  slowlorisWorkers  Int?
  slowPostWorkers   Int?
  notes             String?
}

model Connection {
  id                    String   @id  // nginx $connection
  scenarioId            String?
  ip                    String
  ipSubnet24            String?
  tOpen                 DateTime
  tClose                DateTime?
  durationMs            Int?
  requestCount          Int      @default(0)
  keepaliveUsed         Boolean  @default(false)
  meanRequestTimeMs     Float?
  p95RequestTimeMs      Float?
  maxRequestTimeMs      Float?
  meanInboundByteRate   Float?
  partialRequestCount   Int      @default(0)
  timeoutRequestCount   Int      @default(0)
  tlsVersion            String?
  tlsCipher             String?

  @@index([ip, tOpen])
  @@index([ipSubnet24, tOpen])
  @@index([scenarioId, tOpen])
}

model BehavioralSession {
  // İsim çakışmasın diye 'BehavioralSession' (login session değil)
  sessionIdHash         String   @id
  scenarioId            String?
  firstSeenIp           String?
  distinctIps           Int      @default(1)
  tFirstSeen            DateTime
  tLastSeen             DateTime?
  durationMs            Int?
  requestCount          Int      @default(0)
  uniqueEndpointCount   Int?
  navigationDepth       Int?
  loginPresent          Boolean  @default(false)
  thinkTimeP50Ms        Int?

  @@index([scenarioId, tFirstSeen])
}

model WindowLabel {
  id                 Int      @id @default(autoincrement())
  scenarioId         String
  aggregationType    String   // 'src_ip' | 'src_subnet_24'
  aggregationKey     String
  windowStart        DateTime
  windowEnd          DateTime
  requestCountTotal  Int
  requestCountAttack Int
  attackRatio        Float
  label              String

  @@unique([scenarioId, aggregationType, aggregationKey, windowStart])
  @@index([scenarioId, windowStart])
  @@index([aggregationType, aggregationKey, windowStart])
}

model EndpointCostProfile {
  routeTemplate            String   @id
  method                   String
  sampleCount              Int
  meanDbTimeMs             Float
  meanCpuTimeMs            Float
  meanTotalCostMs          Float
  p95TotalCostMs           Float
  costQuartile             Int      // 1=cheapest, 4=most expensive
  calibrationScenarioId    String?
}

model CalibrationBaseline {
  name           String   @id
  sourceDataset  String
  parameters     Json
  fitQuality     Json
  createdAt      DateTime @default(now())
}
```

### 2.2 Migration oluştur ve uygula

```bash
npx prisma migrate dev --name behavioral_features_v1
```

Hatasız bitmeli. Yeni migration `prisma/migrations/<timestamp>_behavioral_features_v1/`
altında oluştu.

```bash
docker compose exec postgres psql -U research -d ddos_research -c "\dt"
```

Yeni tabloları görmelisin: `Connection`, `BehavioralSession`, `WindowLabel`,
`EndpointCostProfile`, `Scenario`, `CalibrationBaseline`.

### 2.3 Prisma client'ı yenile

```bash
npx prisma generate
```

NestJS otomatik restart eder (start:dev hot reload).

### 2.4 Cheap/medium/expensive endpoint'ler ekle

Sende `/user/search` zaten very expensive. Eksik olanları ekleyelim.

#### 2.4.1 `/health` ve `/ping` (cheap, no-DB)

`src/app.controller.ts` dosyasını şöyle güncelle:

```typescript
import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @Get('health')
  health(): { status: string } {
    return { status: 'ok' };
  }

  @Get('ping')
  ping(): { pong: number } {
    return { pong: Date.now() };
  }
}
```

#### 2.4.2 Medium endpoint: `/users/count`

`src/user/user.controller.ts` içine **JwtAuthGuard'ın DIŞINDA** kalacak şekilde bir
public endpoint eklemek istiyoruz. En temiz yol: ayrı bir module/controller. Ama
hızlı çözüm: aynı controller'da `@UseGuards(JwtAuthGuard)` class-level olduğu için,
public endpoint için **method-level decorator override** kullanalım.

NestJS'te class-level guard'ı method-level'da bypass etmek için custom
`@Public()` decorator ya da farklı controller gerekir. Hızlı ve temiz çözüm: **yeni
bir controller**.

`src/metrics/metrics.controller.ts` oluştur:

```typescript
import { Controller, Get, Query } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Controller('metrics')
export class MetricsController {
  constructor(private prisma: PrismaService) {}

  // CHEAP: tek count, indexli, ms'ler içinde döner
  @Get('users/count')
  async usersCount() {
    const count = await this.prisma.user.count();
    return { count };
  }

  // EXPENSIVE: aggregate over LoginAttempt, indexsiz join-like work
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
```

`src/metrics/metrics.module.ts`:

```typescript
import { Module } from '@nestjs/common';
import { MetricsController } from './metrics.controller';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [MetricsController],
})
export class MetricsModule {}
```

`src/app.module.ts` içinde imports'a ekle:

```typescript
import { MetricsModule } from './metrics/metrics.module';
// ...
imports: [
  ConfigModule.forRoot({ isGlobal: true }),
  LogsModule,
  AuthModule,
  UserModule,
  PrismaModule,
  MetricsModule,  // ← bunu ekle
],
```

### 2.5 Sanity: 4 cost class çalışıyor mu

```bash
# cheap
curl -s -H "x-simulation-label: cost-test" http://localhost:8080/health
curl -s -H "x-simulation-label: cost-test" http://localhost:8080/ping

# medium
curl -s -H "x-simulation-label: cost-test" http://localhost:8080/metrics/users/count

# expensive
curl -s -H "x-simulation-label: cost-test" http://localhost:8080/metrics/reports/login-stats?hours=24

# very expensive (auth gerek; önce kayıt+login yap, token al)
# Kısayol için public bir search variant ekle ya da authentication'lı test et:
TOKEN=$(curl -s -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@x.com","password":"abc12345"}')
echo $TOKEN
# Cevap içinde JWT varsa parse et; yoksa login endpoint'inden al.
```

5 saniye bekle, sonra:

```bash
docker compose exec postgres psql -U research -d ddos_research -c "
SELECT \"routeTemplate\", \"statusCode\", \"responseTimeMs\"
FROM \"RequestLog\"
WHERE \"trafficLabel\"='cost-test'
ORDER BY timestamp DESC LIMIT 10;"
```

`responseTimeMs` kolonunda 4 farklı büyüklükte değer görmelisin (ör. /health → 1-3ms,
/users/count → 5-15ms, /reports/login-stats → 30-200ms).

### 2.6 Day 2 bitti mi?

Checklist:
- [ ] Prisma migration uygulandı, yeni tablolar DB'de
- [ ] `/health`, `/ping`, `/metrics/users/count`, `/metrics/reports/login-stats`
      hepsi 200 dönüyor
- [ ] `RequestLog`'da 4 farklı `routeTemplate` görünüyor, `responseTimeMs` varyans
      yapıyor

Hepsi tikliyse Day 3'e hazırsın.

---

## Day 3 önizlemesi

Day 3'te yapılacaklar (henüz başlama, önce buraya kadar bitir):
- Prisma `$on('query')` hook ile `dbQueryCount`/`dbTotalTimeMs` capture
- `process.cpuUsage()` ile `cpuTimeMs` capture
- `AsyncLocalStorage` ile request scope kontekst
- Middleware'i extend et: yeni alanları doldursun (uaFamily, ipSubnet24, headerCount, vs.)
- Connection-level enrichment için nginx access log → Prisma sync (Python tail script)

Bunları Day 1+2 yeşil olunca yazacağım. Şimdi yapma.

---

## Sık Sorulan Sorunlar (FAQ)

**Q: `host.docker.internal` Linux'ta çalışmıyor.**
Çözüm: `docker-compose.yml`'de `extra_hosts: ["host.docker.internal:host-gateway"]`
satırı zaten var. Yeniden compose up: `docker compose up -d --force-recreate nginx`.

**Q: Mevcut bir Postgres kullanıyorum, çakışma oluyor.**
Çözüm: Local 5432 zaten kullanılıyorsa docker-compose.yml'de `ports: "5433:5432"` yap,
.env'de `localhost:5433` kullan.

**Q: nginx 502 dönüyor.**
NestJS hâlâ çalışıyor mu (`npm run start:dev`)? Aynı zamanda firewall/Docker
networking host.docker.internal'a izin veriyor mu? Doğrula:
```bash
docker compose exec nginx wget -O- http://host.docker.internal:3000/ 2>&1 | tail -5
```

**Q: Migration "shadow database" hatası veriyor.**
`prisma migrate dev` shadow DB ister; Docker container'da postgres user'ın superuser
olduğundan emin ol (default `postgres` image öyle).
