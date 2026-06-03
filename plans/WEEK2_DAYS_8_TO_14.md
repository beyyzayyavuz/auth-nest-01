# Week 2 — Days 8 to 14 Implementation Guide

WEEK1 tamamlandı (5-trace calibration, 17 baseline, full instrumentation).
Bu doküman Week 2'yi adım adım yürütür: k6 refactor sprint (Days 8-9), real
slowloris (Day 10), orchestration ve traffic generation (Day 11), Tier 1 + 2
feature pipeline (Days 12-13), Week 2 checkpoint (Day 14).

> Tüm komutlar projenin kök dizininde çalıştırılır.

---

## DAY 8 — k6 refactor part 1: common modules

**Hedef:** Mevcut k6 script'lerinde kopyala-yapıştır kod var. Ortak modüller
oluşturup harmonize et — özellikle "legitimate user" davranışını tüm
scenario'larda aynı sophistication seviyesinde tut. Critique dökümanındaki
P0 madde 5 (mix script'lerde simplified normal user bias) düzeltmesi.

**Toplam süre:** 4-5 saat

> **Day 8 başlamadan önce zorunlu hazırlık (15 dk):** k6 scenario'larındaki
> `TEST_USERS` (10 hesap, `user01@example.com`...`user10@example.com`)
> NestJS DB'sinde **register edilmiş olmalı**. Aksi halde tüm legitimate
> login attempts 401 dönecek ve hiçbir scenario meaningful trafik üretmeyecek.
>
> Hesapları seed et:
>
> ```bash
> for i in $(seq -w 1 10); do
>   PASSWORDS=("TestUser@2026!" "SecurePass@101" "DemoLogin@2026" \
>              "UserAccess@404" "ProfileTest@55" "SearchUser@77" \
>              "NormalFlow@88" "SessionTest@99" "ApiClient@123" \
>              "TrafficUser@10")
>   IDX=$((10#$i - 1))
>   curl -s -X POST http://localhost:8080/auth/register \
>     -H "Content-Type: application/json" \
>     -d "{\"email\":\"user${i}@example.com\",\"password\":\"${PASSWORDS[$IDX]}\"}"
>   echo
> done
> ```
>
> Sanity:
> ```bash
> docker compose exec postgres psql -U research -d ddos_research \
>   -c "SELECT id, email FROM \"User\" WHERE email LIKE 'user%@example.com';"
> ```
>
> 10 satır görmelisin.

### 8.1 Klasör yapısı

```bash
mkdir -p k6/common
```

Hedef yapı:
```
k6/
├── common/
│   ├── legitimate-user-flow.js     # ortak insan davranışı
│   ├── ip-pool.js                   # overlap'lı IP havuzu
│   ├── ua-pool.js                   # 3-tier UA havuzu
│   └── cadence.js                   # log-normal think helpers
├── scenarios/
│   ├── 01_legitimate_only.js        # mevcut k6-traffics.js refactored
│   ├── 02_http_flood.js             # k6-http-flood refactored
│   ├── 03_low_rate_bot.js           # k6-low-slow → renamed
│   ├── 04_credential_stuffing.js    # YENİ
│   ├── 05_mimicry_flood.js          # YENİ (mimicry holdout)
│   ├── 06_mix_flood.js              # k6-mix-flood refactored
│   ├── 07_mix_slow.js               # k6-mix-slow refactored
│   └── 08_mix_all.js                # k6-mix-all refactored
```

Eski script'leri henüz silme — önce yeniler çalışsın.

### 8.2 Common: cadence helpers

`k6/common/cadence.js`:

```javascript
// Box-Muller standart normal
export function standardNormal() {
  const u1 = Math.max(Math.random(), 1e-9);
  const u2 = Math.random();
  return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
}

// Log-normal sample, clamped
// NASA Jul95 fits: μ_log=2.38, σ_log=1.75 — buradan calibrated default
export function lognormalSample(muLog, sigmaLog, minS = 0.3, maxS = 60) {
  const z = standardNormal();
  const s = Math.exp(muLog + sigmaLog * z);
  return Math.min(Math.max(s, minS), maxS);
}

// Think time tiers — NASA-calibrated parametre uçları
export const THINK = {
  // Sayfa içi (form butonları, modal close)
  short:  () => lognormalSample(0.3, 0.6, 0.2, 5),    // medyan ~1.3s
  // Sayfa geçişleri arası (calibrated to NASA mean ~50s, but capped)
  medium: () => lognormalSample(1.2, 0.8, 0.5, 30),   // medyan ~3.3s
  // Uzun okuma (article, video)
  long:   () => lognormalSample(2.0, 0.9, 1.0, 60),   // medyan ~7.4s
};

// Bot cadence — mekanik uniform yerine log-normal (Section 2.6.4 critique)
// Insan'a yakın görünmek için: median benzer (~2.2s), σ daha dar
export function botCadence(meanSec = 2.2, sigma = 0.3) {
  // mean → μ_log = ln(mean) - σ²/2
  const muLog = Math.log(meanSec) - (sigma * sigma) / 2;
  return lognormalSample(muLog, sigma, 0.5, 10);
}

// Zipf rank sampling (search terms vs)
export function zipfSample(n, alpha = 1.0) {
  const u = Math.max(Math.random(), 1e-9);
  const idx = Math.floor(Math.pow(u, -1 / alpha)) - 1;
  return Math.min(idx, n - 1);
}

// Geometric session length
// p=0.72 → mean ~5-6 pages (NASA-calibrated)
export function sessionLength(bouncePr = 0.20, contPr = 0.72, maxN = 15) {
  if (Math.random() < bouncePr) return 1;
  let n = 2;
  while (Math.random() < contPr && n < maxN) n++;
  return n;
}
```

### 8.3 Common: IP pool (overlap'lı)

`k6/common/ip-pool.js`:

```javascript
// Class-deterministic IP separation YANLIŞ. Botnet-realistic clustering:
// hepsi 192.168.0.0/16 + 10.0.0.0/8 havuzundan, attacker'lar daha küçük
// cluster'lardan ama legit ile overlap.
//
// k6 SharedArray runtime'da her import'ta yeniden değerlendirilemediği için,
// IP havuzlarını function olarak export ediyoruz, scenario'da SharedArray'e
// sarmalanır.

const LEGIT_RANGE = [
  // 50 adet farklı IP — 192.168.x.y aralığı
  ...Array.from({ length: 30 }, (_, i) => `192.168.1.${i + 1}`),
  ...Array.from({ length: 20 }, (_, i) => `10.0.0.${i + 1}`),
];

const ATTACKER_NAIVE = [
  // 20 IP, legit ile overlap'lı
  ...Array.from({ length: 10 }, (_, i) => `192.168.1.${i + 100}`),
  ...Array.from({ length: 5 }, (_, i) => `10.0.0.${i + 50}`),
  ...Array.from({ length: 5 }, (_, i) => `10.0.1.${i + 1}`),
];

const ATTACKER_SOPHISTICATED = [
  // Mimicry: tamamen legit havuzunun içinden + 5 yeni
  ...LEGIT_RANGE.slice(0, 15),
  ...Array.from({ length: 5 }, (_, i) => `192.168.1.${i + 200}`),
];

export function getIpPool(role) {
  switch (role) {
    case 'legit':         return LEGIT_RANGE;
    case 'naive':         return ATTACKER_NAIVE;
    case 'sophisticated': return ATTACKER_SOPHISTICATED;
    default: throw new Error(`Unknown IP role: ${role}`);
  }
}
```

### 8.4 Common: UA pool (3-tier)

`k6/common/ua-pool.js`:

```javascript
// 3-tier UA pool: legit / naive_attacker / sophisticated_attacker
// Sophisticated = legit ile özdeş havuz (mimicry)

export const LEGIT_AGENTS = [
  // StatCounter market share dağılımına yakın, weighted picker'la kullan
  { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36', w: 35 },
  { ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36', w: 15 },
  { ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15', w: 8 },
  { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0', w: 5 },
  { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0', w: 3 },
  { ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1', w: 18 },
  { ua: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36', w: 10 },
  { ua: 'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36', w: 6 },
];

// Naive attacker: tool-revealing UA (curl, python-requests, Go, scripts)
export const NAIVE_ATTACKER_AGENTS = [
  { ua: 'curl/8.7.1', w: 25 },
  { ua: 'curl/7.81.0', w: 15 },
  { ua: 'python-requests/2.31.0', w: 20 },
  { ua: 'Go-http-client/1.1', w: 15 },
  { ua: 'PostmanRuntime/7.36.0', w: 10 },
  { ua: 'Apache-HttpClient/5.3 (Java/17)', w: 8 },
  { ua: 'aiohttp/3.9.1', w: 7 },
];

// Sophisticated attacker: same as legit (mimicry)
export const SOPHISTICATED_ATTACKER_AGENTS = LEGIT_AGENTS;

// Weighted picker
export function pickWeightedUA(pool) {
  const total = pool.reduce((s, it) => s + it.w, 0);
  let r = Math.random() * total;
  for (const it of pool) {
    r -= it.w;
    if (r <= 0) return it.ua;
  }
  return pool[pool.length - 1].ua;
}

// Accept-Language ve Accept-Encoding havuzları
export const ACCEPT_LANGS = [
  'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
  'tr,en-US;q=0.9,en;q=0.8',
  'en-US,en;q=0.9',
  'en-GB,en;q=0.9,tr;q=0.8',
  'tr-TR,tr;q=0.9',
];

export const ACCEPT_ENCS = [
  'gzip, deflate, br',
  'gzip, deflate, br, zstd',
  'gzip, deflate',
];

export function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}
```

### 8.5 Common: legitimate user flow

`k6/common/legitimate-user-flow.js`:

```javascript
// Legitimate insan davranışı — Markov + log-normal think + Zipf search.
// Tüm "normal user" senaryolarında bu modül kullanılır (mix dahil).

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';
import exec from 'k6/execution';
import {
  pickWeightedUA, LEGIT_AGENTS, ACCEPT_LANGS, ACCEPT_ENCS, randomItem,
} from './ua-pool.js';
import { getIpPool } from './ip-pool.js';
import { THINK, sessionLength, zipfSample } from './cadence.js';

// VU state cache (her VU için 1 kez)
const vuStates = {};

// Markov geçiş matrisi — test app endpoint'lerine özgü
const transitionMatrix = {
  start:   { profile: 0.30, search: 0.55, exit: 0.15 },
  profile: { search:  0.55, profile: 0.10, exit: 0.35 },
  search:  { search:  0.45, profile: 0.30, exit: 0.25 },
};

const searchTerms = [
  'güvenlik', 'veri', 'analiz', 'yapay-zeka', 'saldırı',
  'koruma', 'tez', 'fingerprint', 'performans', 'log',
  'authentication', 'token', 'middleware', 'entropy', 'ddos',
];

// Test users — register edilmiş hesaplar
export const TEST_USERS = [
  { email: 'user01@example.com', password: 'TestUser@2026!' },
  { email: 'user02@example.com', password: 'SecurePass@101' },
  { email: 'user03@example.com', password: 'DemoLogin@2026' },
  { email: 'user04@example.com', password: 'UserAccess@404' },
  { email: 'user05@example.com', password: 'ProfileTest@55' },
  { email: 'user06@example.com', password: 'SearchUser@77' },
  { email: 'user07@example.com', password: 'NormalFlow@88' },
  { email: 'user08@example.com', password: 'SessionTest@99' },
  { email: 'user09@example.com', password: 'ApiClient@123' },
  { email: 'user10@example.com', password: 'TrafficUser@10' },
];

export function getVuState(role = 'legit', label = 'normal_user') {
  const vuId = exec.vu.idInTest || 1;
  if (vuStates[vuId]) return vuStates[vuId];

  const ipPool = getIpPool(role);
  const userIdx = (vuId - 1) % TEST_USERS.length;
  const ipIdx = (vuId - 1) % ipPool.length;

  vuStates[vuId] = {
    vuId,
    label,
    user: TEST_USERS[userIdx],
    fakeIp: ipPool[ipIdx],
    userAgent: pickWeightedUA(LEGIT_AGENTS),
    acceptLanguage: randomItem(ACCEPT_LANGS),
    acceptEncoding: randomItem(ACCEPT_ENCS),
    accessToken: null,
    pagesRemaining: sessionLength(),
    lastPageState: 'start',
  };
  return vuStates[vuId];
}

export function buildBaseHeaders(state) {
  return {
    'Content-Type':       'application/json',
    'Accept':             'application/json, text/plain, */*',
    'Accept-Language':    state.acceptLanguage,
    'Accept-Encoding':    state.acceptEncoding,
    'x-simulation-label': state.label,
    'User-Agent':         state.userAgent,
    'x-test-client-ip':   state.fakeIp,
  };
}

export function buildAuthHeaders(state, referer = null) {
  const h = {
    ...buildBaseHeaders(state),
    Authorization: `Bearer ${state.accessToken}`,
  };
  if (referer) h['Referer'] = referer;
  return h;
}

function nextState(current) {
  const dist = transitionMatrix[current] || transitionMatrix.start;
  const r = Math.random();
  let acc = 0;
  for (const [target, p] of Object.entries(dist)) {
    acc += p;
    if (r < acc) return target;
  }
  return 'exit';
}

function pickSearchTerm() {
  return searchTerms[zipfSample(searchTerms.length, 1.0)];
}

export function ensureAuthenticated(state, baseUrl) {
  if (state.accessToken) return true;

  const res = http.post(
    `${baseUrl}/auth/login`,
    JSON.stringify(state.user),
    { headers: buildBaseHeaders(state) },
  );

  if (![200, 201].includes(res.status)) {
    state.accessToken = null;
    return false;
  }
  try { state.accessToken = res.json('accessToken'); }
  catch { return false; }
  if (!state.accessToken) return false;
  THINK.medium();
  return true;
}

export function doProfileRequest(state, baseUrl) {
  if (!ensureAuthenticated(state, baseUrl)) return false;
  const res = http.get(`${baseUrl}/user/profile`,
    { headers: buildAuthHeaders(state, `${baseUrl}/dashboard`) });
  if ([401, 403].includes(res.status)) {
    state.accessToken = null;
    if (!ensureAuthenticated(state, baseUrl)) return false;
  }
  return res.status === 200;
}

export function doSearchRequest(state, baseUrl, maxPage = 5) {
  if (!ensureAuthenticated(state, baseUrl)) return false;
  const term = pickSearchTerm();
  const page = Math.floor(Math.random() * maxPage) + 1;
  const url = `${baseUrl}/user/search?q=${encodeURIComponent(term)}&page=${page}&limit=10`;
  const res = http.get(url, { headers: buildAuthHeaders(state, `${baseUrl}/search`) });
  if ([401, 403].includes(res.status)) {
    state.accessToken = null;
    if (!ensureAuthenticated(state, baseUrl)) return false;
  }
  return res.status === 200;
}

export function doLogoutRequest(state, baseUrl) {
  if (!state.accessToken) return true;
  const res = http.post(`${baseUrl}/auth/logout`, null,
    { headers: buildAuthHeaders(state) });
  state.accessToken = null;
  state.pagesRemaining = sessionLength();
  state.lastPageState = 'start';
  return [200, 201, 204].includes(res.status);
}

// Tek session simülasyonu — tüm normal user senaryolarında çağrılır
export function runLegitSession(baseUrl, role = 'legit', label = 'normal_user') {
  const state = getVuState(role, label);

  group('User Session', function () {
    THINK.short();
    while (state.pagesRemaining > 0) {
      const next = nextState(state.lastPageState);
      if (next === 'exit') break;

      let ok = false;
      if (next === 'profile') ok = doProfileRequest(state, baseUrl);
      else if (next === 'search') ok = doSearchRequest(state, baseUrl, 5);

      if (!ok) { THINK.medium(); break; }
      state.lastPageState = next;
      state.pagesRemaining -= 1;

      if (next === 'profile') THINK.long();
      else THINK.medium();
    }

    // %8 explicit logout
    if (Math.random() < 0.08 && state.accessToken) {
      THINK.medium();
      doLogoutRequest(state, baseUrl);
    } else {
      state.accessToken = null;
      state.pagesRemaining = sessionLength();
      state.lastPageState = 'start';
    }

    // Inter-session gap — heavy-tailed
    THINK.long();
  });
}
```

### 8.6 Refactored: legitimate-only scenario

`k6/scenarios/01_legitimate_only.js`:

```javascript
import { runLegitSession } from '../common/legitimate-user-flow.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const SCENARIO_ID = __ENV.SCENARIO_ID || 'S1_legit_only';

export const options = {
  scenarios: {
    legit_users: {
      executor: 'ramping-vus',
      exec: 'flow',
      startVUs: 0,
      stages: [
        { duration: '2m',  target: 5  },
        { duration: '25m', target: 15 },
        { duration: '3m',  target: 0  },
      ],
      gracefulRampDown: '30s',
      tags: { trafficLabel: 'normal_user', scenarioId: SCENARIO_ID },
    },
  },
};

export function flow() {
  runLegitSession(BASE_URL, 'legit', 'normal_user');
}
```

> Süre: 30 dk core + ramp. Day 11 orchestration'da bu süreyi de scenario_id
> ile DB'ye kaydedeceğiz.

### 8.7 Sanity test

`k6/common/` modülleri import edip basit bir smoke run:

```bash
# k6 yüklü mü?
k6 version

# Quick smoke (10 saniye)
k6 run --duration 10s --vus 2 --env BASE_URL=http://localhost:8080 \
  k6/scenarios/01_legitimate_only.js
```

Beklenen: 10 saniyede 2 VU birkaç request atar, çoğu `/auth/login` +
`/user/search` veya `/user/profile`. NestJS log'unda görmeli sin. RequestLog
tablosunda `trafficLabel='normal_user'` satırlar oluşmalı.

NestJS çalışmıyorsa `npm run start:dev` ile başlat. nginx + postgres docker
compose up halinde olmalı.

### 8.8 Day 8 checkpoint

- [ ] `k6/common/cadence.js`, `ip-pool.js`, `ua-pool.js`,
      `legitimate-user-flow.js` oluştu
- [ ] `k6/scenarios/01_legitimate_only.js` çalışıyor
- [ ] Smoke test 200 OK döndürdü, RequestLog'a satır geldi
- [ ] Mevcut eski script'ler (k6-traffics.js vs.) henüz silinmedi (Day 9'da
      hepsi refactor edilince silinir)

`git commit -am "Day 8: k6 common modules + legitimate scenario refactored"`

---

## DAY 9 — k6 refactor part 2: attack variants + mimicry + credential stuffing

**Hedef:** Saldırı script'lerini common modüllere taşı, naive UA pool'unu
uygula, IP overlap'ı garantile. Yeni iki scenario: credential stuffing,
mimicry flood (mimicry HOLDOUT olacak). **Attack parametrelerini
literatür-grounded şekilde gerekçelendir** (calibration asymmetry düzeltmesi).

**Toplam süre:** 7-8 saat (literatür çalışması + scripting)

### 9.0 Literatür-grounded parameter calibration — TAMAMLANDI (Day 8 öncesi)

> **Status:** Bu adım Day 8 başlamadan önce **tamamen yapıldı**. Verification
> roadmap takip edildi (Kategori A/B/C/D), 4 ciddi LLM hallucination
> yakalandı ve düzeltildi (OWASP OAT mapping, Cloudflare default rate limit,
> Doran 0.5-5 req/s claim, Onaolapo <5% reuse rate).
>
> Mevcut çıktılar:
> - `docs/citation_verification_log.md` — full verification log (17 source)
> - `docs/attack_calibration_sources.md` — verified parameter justification
> - `docs/verification_roadmap.md` — verification protocol dokümantasyonu
>
> Day 9'da bu dosyalardan inline citation yorumlarını k6 script'lerine
> ekleyeceğiz, ek literatür araştırmasına gerek yok.

**Day 9'da kullanılacak verified anchors (`attack_calibration_sources.md`'den):**

| Scenario | Primary anchor | İkincil anchor |
|---|---|---|
| S2 http_flood | Cloudflare 2025 Q1 (94% ≤1 Mrps) | Antonakakis 2017 (Mirai existence) |
| S3 low_rate_bot | Akamai blog 0.5-1.3 req/s | OWASP OAT-011 Scraping |
| S4 credential_stuffing | OWASP OAT-008, Thomas 2017 7-25% match | Akamai SOTI 2024 18.56% broken auth |
| S5 mimicry_flood | Imperva 2025 (21% RP, 46% Chrome) | Wagner-Soto 2002, Fogla 2006 conceptual |
| S6 real_slowloris | slowhttptest tool docs | nginx defaults (60s timeouts) |

K6 script yorum satırlarına bu anchor'ları inline cite et. Örnek:

```javascript
// Per-VU ~1 req/s aggregate 200 req/s peak.
// Anchor: scaled-down lab analog of Cloudflare 2025 Q1 measured
// L7 attacks where 94% remained ≤1 Mrps and 75% < 10 min duration.
// Mirai existence: Antonakakis et al. 2017 (600K device botnet).
maxVUs: 200,
```

**Day 9 başlamadan ön-kontrol:**

1. `docs/attack_calibration_sources.md` aç, scenario'na karşılık gelen
   "Tezdeki cümle" blok'unu kopyala — k6 script yorumuna kısaltılmış
   versiyonunu yapıştır.
2. Verified anchor URL'lerini script header yorumlarında comment olarak
   bulundur (reproducibility için).

### 9.1 HTTP flood (refactored, naive attacker)

`k6/scenarios/02_http_flood.js`:

```javascript
import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
import exec from 'k6/execution';
import { pickWeightedUA, NAIVE_ATTACKER_AGENTS, randomItem } from '../common/ua-pool.js';
import { getIpPool } from '../common/ip-pool.js';
import { TEST_USERS } from '../common/legitimate-user-flow.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const SCENARIO_ID = __ENV.SCENARIO_ID || 'S2_http_flood';

const floodLoginRequests = new Counter('flood_login_requests');
const floodSearchRequests = new Counter('flood_search_requests');
const floodLoginSuccess = new Rate('flood_login_success');

const heavyTerms = ['güvenlik', 'veri', 'analiz', 'koruma', 'tez', 'fingerprint', 'saldırı'];

export const options = {
  scenarios: {
    http_flood: {
      executor: 'ramping-arrival-rate',
      exec: 'flow',
      startRate: 20,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 200,
      stages: [
        { target: 50,  duration: '2m'  },
        { target: 150, duration: '15m' },
        { target: 200, duration: '10m' },  // peak
        { target: 0,   duration: '3m'  },
      ],
      tags: { trafficLabel: 'http_flood', scenarioId: SCENARIO_ID },
    },
  },
};

const profiles = {};
function profile(role = 'naive') {
  const vu = exec.vu.idInTest || 1;
  if (profiles[vu]) return profiles[vu];
  const pool = getIpPool(role);
  profiles[vu] = {
    ip: pool[(vu - 1) % pool.length],
    ua: pickWeightedUA(NAIVE_ATTACKER_AGENTS),
    user: TEST_USERS[(vu - 1) % TEST_USERS.length],
  };
  return profiles[vu];
}

export function flow() {
  const p = profile('naive');
  const baseHeaders = {
    'Content-Type':       'application/json',
    'x-simulation-label': 'http_flood',
    'x-test-client-ip':   p.ip,
    'User-Agent':         p.ua,
  };

  // Login (her iteration'da yeniden)
  floodLoginRequests.add(1, { trafficLabel: 'http_flood' });
  const loginRes = http.post(`${BASE_URL}/auth/login`, JSON.stringify(p.user),
    { headers: baseHeaders });
  const loginOk = [200, 201].includes(loginRes.status);
  floodLoginSuccess.add(loginOk ? 1 : 0, { trafficLabel: 'http_flood' });
  if (!loginOk) return;

  let token;
  try { token = loginRes.json('accessToken'); } catch { return; }
  if (!token) return;

  const authHeaders = { ...baseHeaders, Authorization: `Bearer ${token}` };

  // Burst — 2-5 search hit
  const burst = Math.floor(Math.random() * 4) + 2;
  for (let i = 0; i < burst; i++) {
    floodSearchRequests.add(1, { trafficLabel: 'http_flood' });
    const term = randomItem(heavyTerms);
    http.get(
      `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${(i % 5) + 1}&limit=10`,
      { headers: authHeaders }
    );
    if (i < burst - 1) sleep(0.01 + Math.random() * 0.04); // 10-50ms
  }
}
```

> Volume hedefi: peak 200 req/s. Bu, kritik sınır — backend'i gerçekten
> stress eder. nginx `worker_connections 16384` yeterli, NestJS event loop
> + Prisma pool sınırı çıkacak.

### 9.2 Low-rate bot (eski "low-slow" rename + refactor)

`k6/scenarios/03_low_rate_bot.js`:

```javascript
import http from 'k6/http';
import { sleep, group } from 'k6';
import exec from 'k6/execution';
import { pickWeightedUA, NAIVE_ATTACKER_AGENTS, randomItem } from '../common/ua-pool.js';
import { getIpPool } from '../common/ip-pool.js';
import { botCadence } from '../common/cadence.js';
import { TEST_USERS } from '../common/legitimate-user-flow.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const SCENARIO_ID = __ENV.SCENARIO_ID || 'S3_low_rate_bot';

const RELOGIN_EVERY = 30;
const steadyTerms = ['veri', 'analiz', 'güvenlik'];

export const options = {
  scenarios: {
    low_rate_bot: {
      executor: 'constant-vus',
      exec: 'flow',
      vus: 5,
      duration: '30m',
      tags: { trafficLabel: 'low_rate_bot', scenarioId: SCENARIO_ID },
    },
  },
};

const states = {};
function state() {
  const vu = exec.vu.idInTest || 1;
  if (states[vu]) return states[vu];
  const pool = getIpPool('naive');
  states[vu] = {
    vu,
    ip: pool[(vu - 1) % pool.length],
    ua: pickWeightedUA(NAIVE_ATTACKER_AGENTS),
    user: TEST_USERS[(vu - 1) % TEST_USERS.length],
    token: null,
    stepsSinceLogin: 0,
  };
  return states[vu];
}

export function flow() {
  const s = state();
  const headers = {
    'Content-Type':       'application/json',
    'x-simulation-label': 'low_rate_bot',
    'x-test-client-ip':   s.ip,
    'User-Agent':         s.ua,
  };

  // Re-login periyodik
  if (!s.token || s.stepsSinceLogin >= RELOGIN_EVERY) {
    const r = http.post(`${BASE_URL}/auth/login`, JSON.stringify(s.user),
      { headers });
    if ([200, 201].includes(r.status)) {
      try { s.token = r.json('accessToken'); } catch { s.token = null; }
      s.stepsSinceLogin = 0;
    } else {
      s.token = null;
    }
    sleep(botCadence(2.2));
    return;
  }

  const authHeaders = { ...headers, Authorization: `Bearer ${s.token}` };
  const useSearch = Math.random() < 0.80;
  if (useSearch) {
    const term = randomItem(steadyTerms);
    const page = Math.random() < 0.75 ? 1 : 2;
    http.get(`${BASE_URL}/user/search?q=${term}&page=${page}&limit=10`,
      { headers: authHeaders });
  } else {
    http.get(`${BASE_URL}/user/profile`, { headers: authHeaders });
  }
  s.stepsSinceLogin += 1;

  // Bot cadence — log-normal mean ~2.2s, σ=0.3 (insan'a yakın görünüm)
  sleep(botCadence(2.2, 0.3));
}
```

### 9.3 Credential stuffing (YENİ)

`k6/scenarios/04_credential_stuffing.js`:

```javascript
import http from 'k6/http';
import { sleep } from 'k6';
import { Counter, Rate } from 'k6/metrics';
import exec from 'k6/execution';
import { pickWeightedUA, NAIVE_ATTACKER_AGENTS } from '../common/ua-pool.js';
import { getIpPool } from '../common/ip-pool.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const SCENARIO_ID = __ENV.SCENARIO_ID || 'S4_credential_stuffing';

const stuffingAttempts = new Counter('stuffing_attempts');
const stuffing401Rate = new Rate('stuffing_401_rate');

export const options = {
  scenarios: {
    credential_stuffing: {
      executor: 'ramping-arrival-rate',
      exec: 'flow',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 30,
      maxVUs: 100,
      stages: [
        { target: 30, duration: '2m'  },
        { target: 80, duration: '15m' },
        { target: 100, duration: '10m' },
        { target: 0,  duration: '3m'  },
      ],
      tags: { trafficLabel: 'credential_stuffing', scenarioId: SCENARIO_ID },
    },
  },
};

const states = {};
function state() {
  const vu = exec.vu.idInTest || 1;
  if (states[vu]) return states[vu];
  const pool = getIpPool('naive');
  states[vu] = {
    ip: pool[(vu - 1) % pool.length],
    ua: pickWeightedUA(NAIVE_ATTACKER_AGENTS),
  };
  return states[vu];
}

function randomEmail() {
  return `attacker${Math.random().toString(36).slice(2, 10)}@example.com`;
}

function randomPassword() {
  return Math.random().toString(36).slice(2, 12);
}

export function flow() {
  const s = state();
  stuffingAttempts.add(1);
  const res = http.post(
    `${BASE_URL}/auth/login`,
    JSON.stringify({ email: randomEmail(), password: randomPassword() }),
    {
      headers: {
        'Content-Type':       'application/json',
        'x-simulation-label': 'credential_stuffing',
        'x-test-client-ip':   s.ip,
        'User-Agent':         s.ua,
      },
    }
  );
  stuffing401Rate.add(res.status === 401 ? 1 : 0);
}
```

Beklenen: %95+ 401, yüksek `loginAttempt` insert oranı (DB log).

### 9.4 Mimicry flood (YENİ — HOLDOUT scenario)

`k6/scenarios/05_mimicry_flood.js`:

```javascript
// MIMICRY FLOOD — mimicry holdout test scenario.
// UA: legit havuzu (sophisticated)
// IP: legit'le overlap'lı havuz
// Token-reuse pattern (sticky)
// Burst rate flood seviyesinde
//
// Bu scenario test-only kalmalı (Week 3 Day 17 mimicry holdout).

import http from 'k6/http';
import { sleep } from 'k6';
import exec from 'k6/execution';
import {
  pickWeightedUA, SOPHISTICATED_ATTACKER_AGENTS, randomItem,
  ACCEPT_LANGS, ACCEPT_ENCS,
} from '../common/ua-pool.js';
import { getIpPool } from '../common/ip-pool.js';
import { TEST_USERS } from '../common/legitimate-user-flow.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const SCENARIO_ID = __ENV.SCENARIO_ID || 'S5_mimicry_flood';

const heavyTerms = ['güvenlik', 'veri', 'analiz', 'koruma', 'tez', 'fingerprint', 'saldırı'];

export const options = {
  scenarios: {
    mimicry_flood: {
      executor: 'ramping-arrival-rate',
      exec: 'flow',
      startRate: 20,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 200,
      stages: [
        { target: 50,  duration: '2m'  },
        { target: 150, duration: '15m' },
        { target: 200, duration: '10m' },
        { target: 0,   duration: '3m'  },
      ],
      tags: { trafficLabel: 'mimicry_flood', scenarioId: SCENARIO_ID },
    },
  },
};

const states = {};
function state() {
  const vu = exec.vu.idInTest || 1;
  if (states[vu]) return states[vu];
  const pool = getIpPool('sophisticated');
  states[vu] = {
    ip:   pool[(vu - 1) % pool.length],
    ua:   pickWeightedUA(SOPHISTICATED_ATTACKER_AGENTS),
    lang: randomItem(ACCEPT_LANGS),
    enc:  randomItem(ACCEPT_ENCS),
    user: TEST_USERS[(vu - 1) % TEST_USERS.length],
    token: null,
    iterationCount: 0,
  };
  return states[vu];
}

export function flow() {
  const s = state();
  const headers = {
    'Content-Type':       'application/json',
    'Accept':             'application/json, text/plain, */*',
    'Accept-Language':    s.lang,
    'Accept-Encoding':    s.enc,
    'x-simulation-label': 'mimicry_flood',
    'x-test-client-ip':   s.ip,
    'User-Agent':         s.ua,
  };

  // Token-reuse — flood pattern'in tersine, sadece 50 iteration'da bir login
  if (!s.token || s.iterationCount >= 50) {
    const r = http.post(`${BASE_URL}/auth/login`, JSON.stringify(s.user), { headers });
    if ([200, 201].includes(r.status)) {
      try { s.token = r.json('accessToken'); } catch { s.token = null; }
      s.iterationCount = 0;
    } else { s.token = null; return; }
  }

  const authHeaders = { ...headers, Authorization: `Bearer ${s.token}` };

  // Burst — yine 2-5 search ama sticky token'la
  const burst = Math.floor(Math.random() * 4) + 2;
  for (let i = 0; i < burst; i++) {
    const term = randomItem(heavyTerms);
    http.get(
      `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${(i % 5) + 1}&limit=10`,
      { headers: authHeaders }
    );
    if (i < burst - 1) sleep(0.01 + Math.random() * 0.04);
  }
  s.iterationCount += 1;
}
```

> Bu scenario Week 3 Day 17'de **train'de değil sadece test'te** kullanılır.
> Mimicry-attack-holdout deneyinin direkt empirik testi.

### 9.5 Refactor mix scripts

`k6-mix-flood.js`, `k6-mix-slow.js`, `k6-mix-all.js` zaten var — sadece
"normal user" tarafını `runLegitSession()` ile değiştirip attack tarafını da
common'a taşı. Detayları çok uzun, prensip:

```javascript
// k6/scenarios/06_mix_flood.js
import { runLegitSession } from '../common/legitimate-user-flow.js';
// flood flow'u 02_http_flood'dan import et veya tekrarla

export const options = {
  scenarios: {
    normal: {
      executor: 'ramping-vus',
      exec: 'normalFlow',
      stages: [...],
      tags: { trafficLabel: 'normal_user_mix_flood' },
    },
    flood: {
      executor: 'ramping-arrival-rate',
      exec: 'floodFlow',
      stages: [...],
      tags: { trafficLabel: 'http_flood_mix' },
    },
  },
};

export function normalFlow() {
  runLegitSession(BASE_URL, 'legit', 'normal_user_mix_flood');
}
export function floodFlow() {
  // 02_http_flood.js'den flow() function'ını çağır veya tekrar yaz
}
```

### 9.6 Eski script'leri arşivle

Yeniler çalıştığını doğruladıktan sonra:

```bash
mkdir -p k6/_legacy
mv k6-traffics.js k6-http-flood.js k6-low-slow.js \
   k6-mix-flood.js k6-mix-slow.js k6-mix-all.js \
   k6/_legacy/
```

Tezde "previous iteration of traffic generator scripts retained in
`k6/_legacy/` for reproducibility" diye yaz.

### 9.7 Sanity (her yeni scenario için 30s smoke)

```bash
for s in 02_http_flood 03_low_rate_bot 04_credential_stuffing 05_mimicry_flood; do
  echo "=== $s ==="
  k6 run --duration 30s --env BASE_URL=http://localhost:8080 \
    k6/scenarios/$s.js
done
```

Her scenario'da:
- 200 OK / 401 / 429 dönüş kodları beklenen
- RequestLog tablosunda doğru `trafficLabel` ile satırlar oluşuyor
- IP/UA değerleri schema'ya göre doğru atanmış

```bash
docker compose exec postgres psql -U research -d ddos_research -c "
SELECT \"trafficLabel\", COUNT(*), COUNT(DISTINCT ip), COUNT(DISTINCT \"uaFamily\")
FROM \"RequestLog\"
WHERE timestamp > NOW() - INTERVAL '5 minutes'
GROUP BY \"trafficLabel\";"
```

Beklenen: her scenario için kendi label'ı, distinct IP > 1, distinct UA
family > 1.

### 9.8 Day 9 checkpoint

- [x] `docs/attack_calibration_sources.md` her referans Google Scholar'da
      doğrulandı (citation count, DOI, yıl) — **Day 8 öncesi tamamlandı**
- [x] Bibtex collection hazır — **`attack_calibration_sources.md` içinde**
- [ ] k6 script'lerine inline parameter citation yorumları eklendi
- [ ] 5 yeni scenario script (`02`-`05`) oluştu, smoke testleri geçti
- [ ] Mix script'ler refactored (`06`-`08`)
- [ ] Eski script'ler `k6/_legacy/`'ye taşındı
- [ ] DB sanity: distinct UA family > 1 her scenario'da
- [ ] Mimicry flood scenario'sunda IP/UA legit ile overlap'lı (eyeball)

`git commit -am "Day 9: 5 attack scenarios + mix refactor + inline citation comments"`

---

## DAY 10 — Real slow-loris (slowhttptest container)

**Hedef:** Gerçek L7 slow-loris attack — k6 ile yapılamaz çünkü partial HTTP
header gönderme TCP-level. `slowhttptest` Docker container'da.

**Toplam süre:** 3-4 saat

### 10.1 Dockerfile

`infra/slowhttptest/Dockerfile`:

```dockerfile
FROM alpine:3.19

RUN apk add --no-cache slowhttptest curl

# Default no-op; gerçek komut docker compose run ile verilir
CMD ["sleep", "infinity"]
```

### 10.2 docker-compose.yml ekle

`docker-compose.yml`'e service ekle:

```yaml
  slowhttptest:
    build: ./infra/slowhttptest
    container_name: ddos_slowhttptest
    extra_hosts:
      - "host.docker.internal:host-gateway"
    profiles:
      - attack    # default'ta başlamasın, manuel start
```

`profiles: ["attack"]` sayesinde `docker compose up -d` bunu başlatmaz.
Manuel: `docker compose --profile attack up -d slowhttptest`.

### 10.3 Build

```bash
docker compose build slowhttptest
docker compose --profile attack up -d slowhttptest
docker compose exec slowhttptest slowhttptest -h | head -5
```

`slowhttptest` help mesajı görmelisin.

### 10.4 Üç attack mode

#### Slowloris (incomplete header)
```bash
docker compose exec slowhttptest \
  slowhttptest -c 500 -H -i 10 -r 50 -t GET \
    -u http://host.docker.internal:8080/ -x 24 -p 3
```

- `-c 500`: 500 paralel connection
- `-H`: incomplete header attack
- `-i 10`: 10s aralıkla interval
- `-r 50`: connection rate 50/s
- `-x 24`: max 24s send delay
- `-p 3`: probe interval

#### Slow-POST (RUDY)
```bash
docker compose exec slowhttptest \
  slowhttptest -c 500 -B -i 110 -r 50 -t POST \
    -u http://host.docker.internal:8080/auth/login \
    -x 60 -p 3 \
    -H "Content-Type: application/json"
```

- `-B`: slow body (RUDY)
- POST body 1 byte/110s hızında dripped

#### Slow-read
```bash
docker compose exec slowhttptest \
  slowhttptest -c 500 -X -r 50 \
    -u "http://host.docker.internal:8080/user/search?q=test"
```

- `-X`: slow read (TCP receive window manipulation)

> NOT: Slow-loris ve slow-POST için NestJS auth-protected endpoint'leri
> kullanmıyoruz çünkü auth check connection'ı erken kapatabilir. /
> (root) ve /auth/login (POST, body slow-drip) ideal.

### 10.5 Sanity — saldırı gerçekten etkiliyor mu?

Bir terminal'de slowloris başlat. Başka terminal'de meşru request:

```bash
# Slowloris çalışırken
time curl -s http://localhost:8080/health
```

Beklenen:
- Slowloris başlamadan: response < 50ms
- Slowloris çalışırken: response yavaşlamış olabilir veya timeout
  (connection slot doluysa)
- nginx access log'da partial request status (408) görmelisin

```bash
tail -f infra/nginx/logs/ddos_research.log | grep '"status":"408"'
```

408 (timeout) status code'ları slowloris sırasında çoğalmalı. Bu, real
slow-loris detection feature'larının (`partial_request_flag`, status=408)
çalışacağının garantisi.

### 10.6 Slowhttptest scenario script

`scripts/run-slowhttp.sh`:

```bash
#!/bin/bash
set -e
MODE="${1:-slowloris}"
DURATION="${2:-1800}"  # 30 dakika

case "$MODE" in
  slowloris)
    docker compose exec slowhttptest \
      slowhttptest -c 500 -H -i 10 -r 50 -t GET \
        -u http://host.docker.internal:8080/ \
        -x 24 -p 3 -l "$DURATION"
    ;;
  slow_post)
    docker compose exec slowhttptest \
      slowhttptest -c 500 -B -i 110 -r 50 -t POST \
        -u http://host.docker.internal:8080/auth/login \
        -x 60 -p 3 -l "$DURATION" \
        -H "Content-Type: application/json"
    ;;
  slow_read)
    docker compose exec slowhttptest \
      slowhttptest -c 500 -X -r 50 \
        -u "http://host.docker.internal:8080/user/search?q=test" \
        -l "$DURATION"
    ;;
  *)
    echo "Unknown mode: $MODE. Use slowloris|slow_post|slow_read"
    exit 1
    ;;
esac
```

```bash
chmod +x scripts/run-slowhttp.sh
```

### 10.7 Day 10 checkpoint

- [ ] Slowhttptest container build edildi, çalışıyor
- [ ] Üç mode (slowloris, slow_post, slow_read) test edildi
- [ ] Slowloris çalışırken nginx access log'da 408 status artıyor
- [ ] `partial_request_flag` RequestLog'da çoğalıyor
- [ ] `run-slowhttp.sh` scenario script'i hazır

`git commit -am "Day 10: slowhttptest container + 3 attack modes"`

---

## DAY 11 — Orchestration + 30dk × 6 scenario overnight run

**Hedef:** 6 scenario'yu sıralı/paralel çalıştır, her birini 30 dakika
sürdür, recovery period ekle, scenario_id'yi DB'ye yaz. **Veriyi gece
oluştur** — sabaha 3.5 saatlik gerçekçi trafik DB'de hazır.

**Toplam süre:** 4 saat (kod + setup), 4 saat overnight (otomatik)

### 11.1 Scenario tanımları

`scripts/scenarios.json`:

```json
{
  "S1_legit_only": {
    "description": "Legitimate traffic baseline (cost calibration source)",
    "k6_scripts": ["01_legitimate_only"],
    "slowhttp_modes": [],
    "duration_min": 30
  },
  "S2_http_flood": {
    "description": "Legit + HTTP flood (naive UA, IP overlap)",
    "k6_scripts": ["01_legitimate_only", "02_http_flood"],
    "slowhttp_modes": [],
    "duration_min": 30
  },
  "S3_low_rate_bot": {
    "description": "Legit + low-rate scraping bot",
    "k6_scripts": ["01_legitimate_only", "03_low_rate_bot"],
    "slowhttp_modes": [],
    "duration_min": 30
  },
  "S4_credential_stuffing": {
    "description": "Legit + credential stuffing (95%+ 401)",
    "k6_scripts": ["01_legitimate_only", "04_credential_stuffing"],
    "slowhttp_modes": [],
    "duration_min": 30
  },
  "S5_mimicry_flood": {
    "description": "Legit + mimicry flood (HOLDOUT, test-only)",
    "k6_scripts": ["01_legitimate_only", "05_mimicry_flood"],
    "slowhttp_modes": [],
    "duration_min": 30
  },
  "S6_slowloris": {
    "description": "Legit + real slowloris + slow-POST",
    "k6_scripts": ["01_legitimate_only"],
    "slowhttp_modes": ["slowloris", "slow_post"],
    "duration_min": 30
  }
}
```

### 11.2 Scenario kayıt ve master orchestration

`scripts/run-all-scenarios.sh`:

```bash
#!/bin/bash
set -e

SCENARIOS_FILE="scripts/scenarios.json"
RECOVERY_MIN=3
DURATION_PER_SCENARIO=30  # dakika

# Postgres'e scenario insert helper
insert_scenario() {
  local id="$1"
  local desc="$2"
  local started="$3"
  docker compose exec -T postgres psql -U research -d ddos_research -c "
    INSERT INTO \"Scenario\" (id, name, description, \"startedAt\", \"endedAt\")
    VALUES ('$id', '$id', '$desc', '$started', NULL)
    ON CONFLICT (id) DO UPDATE SET \"startedAt\" = EXCLUDED.\"startedAt\";
  "
}

end_scenario() {
  local id="$1"
  local ended="$2"
  docker compose exec -T postgres psql -U research -d ddos_research -c "
    UPDATE \"Scenario\" SET \"endedAt\"='$ended' WHERE id='$id';
  "
}

run_scenario() {
  local id="$1"
  local k6_scripts="$2"      # comma-separated
  local slowhttp_modes="$3"  # comma-separated
  local duration_min="$4"

  echo "==================================================="
  echo "Scenario: $id (${duration_min} min)"
  echo "==================================================="

  local started=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  insert_scenario "$id" "$id scenario" "$started"

  local pids=()

  # k6 scripts (background)
  IFS=',' read -ra K6_ARR <<< "$k6_scripts"
  for script in "${K6_ARR[@]}"; do
    [ -z "$script" ] && continue
    echo "  Starting k6 $script..."
    SCENARIO_ID="$id" \
      k6 run --duration "${duration_min}m" \
        --env "BASE_URL=http://localhost:8080" \
        --env "SCENARIO_ID=$id" \
        "k6/scenarios/$script.js" \
        > "logs/${id}_${script}.log" 2>&1 &
    pids+=($!)
  done

  # slowhttptest modes (background)
  if [ -n "$slowhttp_modes" ]; then
    IFS=',' read -ra SLOW_ARR <<< "$slowhttp_modes"
    for mode in "${SLOW_ARR[@]}"; do
      [ -z "$mode" ] && continue
      echo "  Starting slowhttp $mode..."
      ./scripts/run-slowhttp.sh "$mode" $((duration_min * 60)) \
        > "logs/${id}_${mode}.log" 2>&1 &
      pids+=($!)
    done
  fi

  # Hepsinin bitmesini bekle
  for pid in "${pids[@]}"; do
    wait "$pid" || echo "  Process $pid exited with non-zero"
  done

  local ended=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  end_scenario "$id" "$ended"

  echo "  Scenario ended. Recovery period (${RECOVERY_MIN} min legit-only)..."
  SCENARIO_ID="${id}_recovery" \
    k6 run --duration "${RECOVERY_MIN}m" \
      --env "BASE_URL=http://localhost:8080" \
      --env "SCENARIO_ID=${id}_recovery" \
      "k6/scenarios/01_legitimate_only.js" \
      > "logs/${id}_recovery.log" 2>&1
}

mkdir -p logs

# Sırayla çalıştır
run_scenario "S1_legit_only"           "01_legitimate_only" ""                    30
run_scenario "S2_http_flood"           "01_legitimate_only,02_http_flood" ""      30
run_scenario "S3_low_rate_bot"         "01_legitimate_only,03_low_rate_bot" ""    30
run_scenario "S4_credential_stuffing"  "01_legitimate_only,04_credential_stuffing" "" 30
run_scenario "S5_mimicry_flood"        "01_legitimate_only,05_mimicry_flood" ""   30
run_scenario "S6_slowloris"            "01_legitimate_only" "slowloris,slow_post" 30

echo "All scenarios completed."
```

```bash
chmod +x scripts/run-all-scenarios.sh
```

### 11.3 Önce kısa smoke run

Tüm orchestrator'ı 30 dakika x 6 = 3 saat öncesinde test etmek istemezsin.
Önce her scenario'yu **1 dakika** ile dene:

```bash
# Geçici: scripts/run-all-scenarios.sh içinde duration_min'i 1'e indir
# Smoke run
./scripts/run-all-scenarios.sh

# Sonra 30'a geri al
```

Beklenen: 6 × ~4 dakika ≈ 24 dakikada toplam smoke run biter. Her scenario
RequestLog'a satır yazıyor mu, Scenario tablosunda kayıtlar var mı doğrula:

```bash
docker compose exec postgres psql -U research -d ddos_research -c "
SELECT id, \"startedAt\", \"endedAt\",
  (SELECT COUNT(*) FROM \"RequestLog\" WHERE \"scenarioId\" = s.id) AS req_count
FROM \"Scenario\" s ORDER BY \"startedAt\";"
```

### 11.4 Gerçek overnight run

Smoke OK ise duration'ı 30'a geri al, gece çalıştır:

```bash
nohup ./scripts/run-all-scenarios.sh > logs/orchestrator.log 2>&1 &
disown
```

`nohup` + `disown` sayesinde terminal kapansa bile devam eder. 4-5 saatte
biter. Sabah `logs/orchestrator.log` ve DB'yi kontrol edersin.

### 11.5 Sabah sanity (overnight run sonrası)

```bash
docker compose exec postgres psql -U research -d ddos_research -c "
SELECT \"scenarioId\", \"trafficLabel\", COUNT(*) AS n,
  AVG(\"responseTimeMs\")::numeric(8,2) AS avg_ms,
  SUM(CASE WHEN \"statusCode\">=400 THEN 1 ELSE 0 END) AS errs
FROM \"RequestLog\"
WHERE \"scenarioId\" IS NOT NULL
GROUP BY \"scenarioId\", \"trafficLabel\"
ORDER BY \"scenarioId\";"
```

Beklenen:
- S1: ~10K-30K legit request, %99 200 OK, low latency
- S2: ~150K-300K http_flood request, mixed status
- S3: ~5K low_rate_bot, low rate
- S4: ~80K credential_stuffing, %95+ 401
- S5: ~150K-300K mimicry_flood
- S6: legit + slowloris connections (slowloris kendisi RequestLog'a yazılmaz —
  partial timeout 408 olarak nginx tarafından yazılır)

### 11.6 Day 11 checkpoint

- [ ] 6 scenario tanımlandı, orchestrator hazır
- [ ] Smoke run 24 dakikada bitti, her scenario satır üretti
- [ ] Overnight run gece çalışıyor (veya bitmiş)
- [ ] Sabah sanity: her scenario beklenen aralıkta data üretti
- [ ] Recovery period'lar her scenario sonunda var

`git commit -am "Day 11: orchestration + 6 scenarios + overnight data generation"`

---

## DAY 12 — Tier 1 connection-level pipeline

**Hedef:** Per-connection metric'leri RequestLog'dan derive et, `Connection`
tablosuna yaz. Slow-loris detection için en kritik adım.

**Toplam süre:** 3-4 saat

### 12.1 Connection extractor script

`analysis/scripts/10_tier1_connections.py`:

```python
"""
Tier 1: per-connection feature extraction.
RequestLog → Connection table.
"""

import psycopg2
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

conn = psycopg2.connect(
    host='localhost', port=5432, user='research', password='research',
    database='ddos_research',
)

print('Loading RequestLog with connection info...')
df = pd.read_sql("""
    SELECT id, "connId", "connRequestIndex",
           ip, "ipSubnet24", "scenarioId",
           timestamp, "responseTimeMs", "statusCode", "partialRequest"
    FROM "RequestLog"
    WHERE "connId" IS NOT NULL
""", conn)

print(f'  Loaded {len(df):,} requests with connId')
print(f'  Distinct connections: {df["connId"].nunique():,}')

# Per-connection aggregation
agg = df.groupby('connId').agg(
    scenarioId=('scenarioId', 'first'),
    ip=('ip', 'first'),
    ipSubnet24=('ipSubnet24', 'first'),
    tOpen=('timestamp', 'min'),
    tClose=('timestamp', 'max'),
    request_count=('id', 'count'),
    mean_request_time_ms=('responseTimeMs', 'mean'),
    p95_request_time_ms=('responseTimeMs', lambda x: x.quantile(0.95)),
    max_request_time_ms=('responseTimeMs', 'max'),
    partial_request_count=('partialRequest', 'sum'),
    timeout_request_count=('statusCode', lambda x: (x == 408).sum()),
).reset_index()

agg['durationMs'] = (agg['tClose'] - agg['tOpen']).dt.total_seconds() * 1000
agg['keepaliveUsed'] = agg['request_count'] > 1

print(f'  Aggregated to {len(agg):,} connections')

# Connection table'a yaz
print('Writing to Connection table...')
cur = conn.cursor()
cur.execute('TRUNCATE "Connection"')

records = agg.to_dict(orient='records')
batch_sql = """
INSERT INTO "Connection"
  (id, "scenarioId", ip, "ipSubnet24", "tOpen", "tClose", "durationMs",
   "requestCount", "keepaliveUsed", "meanRequestTimeMs",
   "p95RequestTimeMs", "maxRequestTimeMs", "partialRequestCount",
   "timeoutRequestCount")
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
"""
for r in records:
    cur.execute(batch_sql, (
        r['connId'], r['scenarioId'], r['ip'], r['ipSubnet24'],
        r['tOpen'], r['tClose'], int(r['durationMs']) if pd.notna(r['durationMs']) else None,
        int(r['request_count']),
        bool(r['keepaliveUsed']),
        float(r['mean_request_time_ms']) if pd.notna(r['mean_request_time_ms']) else None,
        float(r['p95_request_time_ms']) if pd.notna(r['p95_request_time_ms']) else None,
        float(r['max_request_time_ms']) if pd.notna(r['max_request_time_ms']) else None,
        int(r['partial_request_count']),
        int(r['timeout_request_count']),
    ))

conn.commit()
cur.close()
conn.close()
print(f'  Inserted {len(records):,} Connection rows')
```

```bash
python analysis/scripts/10_tier1_connections.py
```

### 12.2 KRİTİK SANITY: real slowloris connection feature'ları farklı mı?

```bash
docker compose exec postgres psql -U research -d ddos_research -c "
SELECT \"scenarioId\",
  COUNT(*) AS n,
  AVG(\"durationMs\")::numeric(10,2) AS avg_dur_ms,
  AVG(\"requestCount\")::numeric(8,2) AS avg_req_per_conn,
  AVG(\"meanRequestTimeMs\")::numeric(10,2) AS avg_req_time,
  SUM(\"partialRequestCount\") AS total_partial,
  SUM(\"timeoutRequestCount\") AS total_timeouts
FROM \"Connection\"
WHERE \"scenarioId\" IS NOT NULL
GROUP BY \"scenarioId\"
ORDER BY \"scenarioId\";"
```

**Beklenen kritik fark:**
- S1, S2, S3, S4, S5: `total_timeouts` ≈ 0, `mean_request_time` <500ms,
  `duration` orta
- **S6 (slowloris): `total_timeouts` >> 0, `mean_request_time` >> hepsinden,
  `duration` çok yüksek**

Eğer S6'da farklılık görünmüyorsa Day 10'daki slowloris setup'ı çalışmamış,
geri dön debug et.

### 12.3 Day 12 checkpoint

- [ ] Connection tablosu doldu
- [ ] S6 (slowloris) connection feature'ları diğer scenario'lardan **istatistiksel anlamlı farklı**
- [ ] Mann-Whitney U testi: S6 vs S1 partial_request_count, p<0.001 olmalı

`git commit -am "Day 12: Tier 1 connection-level pipeline + slowloris validation"`

---

## DAY 13 — Tier 2 windowed aggregation + endpoint cost calibration

**Hedef:** Per-(src_ip, 10s_window) ve per-(src_subnet_24, 10s_window) feature
vektörleri üret. Window labels (ground truth) yaz. Endpoint cost vektörü
S1 trafiğinden çıkar.

**Toplam süre:** 5-6 saat

### 13.1 Endpoint cost calibration (önce bu)

`analysis/scripts/11_endpoint_cost.py`:

```python
"""
S1 (legitimate-only) trafiğinden her route için mean backend cost çıkar.
EndpointCostProfile tablosuna yaz.
"""

import psycopg2
import pandas as pd
from pathlib import Path

conn = psycopg2.connect(
    host='localhost', port=5432, user='research', password='research',
    database='ddos_research',
)

print('Loading S1 RequestLog...')
df = pd.read_sql("""
    SELECT "routeTemplate", method,
           "dbTotalTimeMs", "cpuTimeMs", "responseTimeMs"
    FROM "RequestLog"
    WHERE "scenarioId" = 'S1_legit_only'
""", conn)

print(f'  {len(df):,} legit requests')

df['totalCost'] = df['dbTotalTimeMs'] + df['cpuTimeMs']

agg = df.groupby(['routeTemplate', 'method']).agg(
    sample_count=('totalCost', 'count'),
    mean_db_time_ms=('dbTotalTimeMs', 'mean'),
    mean_cpu_time_ms=('cpuTimeMs', 'mean'),
    mean_total_cost_ms=('totalCost', 'mean'),
    p95_total_cost_ms=('totalCost', lambda x: x.quantile(0.95)),
).reset_index()

# Cost quartile (1=cheapest, 4=most expensive)
agg['cost_quartile'] = pd.qcut(agg['mean_total_cost_ms'], 4, labels=[1, 2, 3, 4]).astype(int)

print('\nEndpoint cost profile:')
print(agg.to_string())

cur = conn.cursor()
cur.execute('TRUNCATE "EndpointCostProfile"')
for r in agg.to_dict(orient='records'):
    cur.execute("""
        INSERT INTO "EndpointCostProfile"
          ("routeTemplate", method, "sampleCount", "meanDbTimeMs", "meanCpuTimeMs",
           "meanTotalCostMs", "p95TotalCostMs", "costQuartile", "calibrationScenarioId")
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        r['routeTemplate'], r['method'], int(r['sample_count']),
        float(r['mean_db_time_ms']), float(r['mean_cpu_time_ms']),
        float(r['mean_total_cost_ms']), float(r['p95_total_cost_ms']),
        int(r['cost_quartile']), 'S1_legit_only',
    ))

conn.commit()
cur.close()
conn.close()
print(f'\nSaved {len(agg)} routes to EndpointCostProfile')
```

```bash
python analysis/scripts/11_endpoint_cost.py
```

Sanity:
```bash
docker compose exec postgres psql -U research -d ddos_research -c "
SELECT * FROM \"EndpointCostProfile\" ORDER BY \"meanTotalCostMs\";"
```

Beklenen: /health, /ping en ucuz (Q1); /user/search, /metrics/reports/...
en pahalı (Q4).

### 13.2 Tier 2 windowed aggregation

`analysis/scripts/12_tier2_features.py`:

```python
"""
Per-(src_ip, 10s_window) ve per-(src_subnet_24, 10s_window) feature vektörü.
Output: parquet (Pandas-bound, DB'ye gerek yok şu aşamada).
"""

import psycopg2
import pandas as pd
import numpy as np
from pathlib import Path
from scipy.stats import skew, kurtosis

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'data/features'
OUT.mkdir(parents=True, exist_ok=True)

WINDOW_SEC = 10
SLIDE_SEC = 1

conn = psycopg2.connect(
    host='localhost', port=5432, user='research', password='research',
    database='ddos_research',
)

print('Loading RequestLog + EndpointCostProfile...')
req = pd.read_sql("""
    SELECT id, timestamp, ip, "ipSubnet24", "routeTemplate",
           "responseTimeMs", "dbQueryCount", "dbTotalTimeMs", "cpuTimeMs",
           "statusCode", "uaFamily", "loginPresent", "scenarioId",
           "trafficLabel", "partialRequest"
    FROM "RequestLog"
    WHERE "scenarioId" IS NOT NULL
""", conn)
req['timestamp'] = pd.to_datetime(req['timestamp'], utc=True)
print(f'  {len(req):,} requests across {req["scenarioId"].nunique()} scenarios')

cost_profile = pd.read_sql(
    'SELECT "routeTemplate", "meanTotalCostMs" FROM "EndpointCostProfile"',
    conn
).set_index('routeTemplate')['meanTotalCostMs'].to_dict()

req['endpoint_cost'] = req['routeTemplate'].map(cost_profile).fillna(0)

# Time bucketing — 1s slide, 10s window. Pandas için tumbling 1s + rolling
req['bucket_1s'] = req['timestamp'].dt.floor('1s')

def shannon_entropy(values):
    if len(values) == 0: return 0.0
    counts = pd.Series(values).value_counts()
    p = counts / counts.sum()
    return float(-(p * np.log2(p)).sum())

def aggregate_window(group, key_col):
    """Tek bir (key, bucket) grubu üzerinde feature'lar."""
    if len(group) < 2:
        return None
    iats = group['timestamp'].diff().dt.total_seconds().dropna().values
    return {
        'aggregation_type': key_col,
        'aggregation_key': group.iloc[0][key_col] if pd.notna(group.iloc[0][key_col]) else None,
        'window_start': group['bucket_1s'].min(),
        'window_end': group['bucket_1s'].max(),
        'request_count': len(group),
        'req_rate': len(group) / WINDOW_SEC,
        'iat_mean': float(np.mean(iats)) if len(iats) else 0,
        'iat_std': float(np.std(iats)) if len(iats) else 0,
        'iat_cv': float(np.std(iats) / np.mean(iats)) if len(iats) and np.mean(iats) > 0 else 0,
        'iat_skew': float(skew(iats)) if len(iats) > 2 else 0,
        'iat_p95': float(np.percentile(iats, 95)) if len(iats) else 0,
        'endpoint_unique': group['routeTemplate'].nunique(),
        'endpoint_entropy': shannon_entropy(group['routeTemplate']),
        'endpoint_cost_sum': float(group['endpoint_cost'].sum()),
        'endpoint_cost_mean': float(group['endpoint_cost'].mean()),
        'ua_unique': group['uaFamily'].nunique(),
        'ua_entropy': shannon_entropy(group['uaFamily']),
        'mean_response_time': float(group['responseTimeMs'].mean()),
        'mean_db_time': float(group['dbTotalTimeMs'].mean()),
        'mean_cpu_time': float(group['cpuTimeMs'].mean()),
        'sum_db_queries': int(group['dbQueryCount'].sum()),
        'status_4xx_ratio': float((group['statusCode'].between(400, 499)).mean()),
        'status_5xx_ratio': float((group['statusCode'].between(500, 599)).mean()),
        'status_404_ratio': float((group['statusCode'] == 404).mean()),
        'status_408_ratio': float((group['statusCode'] == 408).mean()),
        'partial_ratio': float(group['partialRequest'].mean()),
        'login_present_ratio': float(group['loginPresent'].mean()),
        'scenario_id': group.iloc[0]['scenarioId'],
        'majority_label': group['trafficLabel'].mode().iloc[0] if len(group['trafficLabel'].mode()) else 'unlabeled',
    }

results = []
for key_col in ['ip', 'ipSubnet24']:
    print(f'\nAggregating by {key_col}...')
    # Per (key, bucket_1s) — sonra rolling 10s window
    # Basitleştirme: bucket_10s tumbling (sliding değil) v1'de
    req['bucket_10s'] = req['timestamp'].dt.floor(f'{WINDOW_SEC}s')
    grouped = req.groupby([key_col, 'bucket_10s'])
    n = 0
    for (k, b), g in grouped:
        feat = aggregate_window(g, key_col)
        if feat:
            results.append(feat)
        n += 1
        if n % 10000 == 0:
            print(f'  {n:,} groups processed')

feats_df = pd.DataFrame(results)
print(f'\nTotal feature rows: {len(feats_df):,}')

# WindowLabel ground truth
print('\nWriting WindowLabel...')
cur = conn.cursor()
cur.execute('TRUNCATE "WindowLabel"')

for r in feats_df.to_dict(orient='records'):
    if not r['aggregation_key']:
        continue
    # tie-breaker: 80%+ legit ise legitimate, ≥20% attack ise dominant attack class
    label = r['majority_label']
    cur.execute("""
        INSERT INTO "WindowLabel"
          ("scenarioId", "aggregationType", "aggregationKey",
           "windowStart", "windowEnd",
           "requestCountTotal", "requestCountAttack",
           "attackRatio", label)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT DO NOTHING
    """, (
        r['scenario_id'], r['aggregation_type'], str(r['aggregation_key']),
        r['window_start'], r['window_end'],
        int(r['request_count']),
        int(r['request_count']) if 'flood' in label or 'bot' in label or 'stuffing' in label else 0,
        1.0 if ('flood' in label or 'bot' in label or 'stuffing' in label) else 0.0,
        label,
    ))

conn.commit()

# Tier 2 features parquet
feats_df.to_parquet(OUT / 'tier2_features.parquet', compression='snappy')
print(f'\nSaved features to {OUT / "tier2_features.parquet"}')

cur.close()
conn.close()
```

```bash
python analysis/scripts/12_tier2_features.py
```

> **Performans uyarısı:** Bu script büyük veri ile yavaş olabilir
> (overnight 6 scenario × 30dk = ~500K-1M request, 10s window → ~50K window).
> Eğer >30 dakika sürerse `dask` veya chunk-based processing'e geç. v1 için
> kabul edilebilir.

### 13.3 Sanity — feature dağılımı sınıflara göre farklı mı?

```python
# Quick sanity Python:
python -c "
import pandas as pd
df = pd.read_parquet('analysis/data/features/tier2_features.parquet')
print('--- mean by scenario ---')
print(df.groupby('scenario_id')[['req_rate', 'iat_cv', 'endpoint_entropy', 'endpoint_cost_sum', 'partial_ratio']].mean().round(3))
"
```

Beklenen yapısal farklar:
- **req_rate:** flood/mimicry yüksek, low_rate_bot düşük, slowloris orta-düşük (request count düşük çünkü partial)
- **iat_cv:** flood düşük (regular), low_rate_bot çok düşük (sabit cadence), legit yüksek
- **endpoint_entropy:** legit yüksek, flood/credential_stuffing düşük
- **endpoint_cost_sum:** flood'da yüksek (search bombing), credential stuffing'de düşük (sadece /auth/login)
- **partial_ratio:** S6 slowloris'te yüksek, diğerlerinde sıfıra yakın

### 13.4 Day 13 checkpoint

- [ ] EndpointCostProfile dolu, 4 quartile var
- [ ] Tier 2 features parquet oluştu
- [ ] WindowLabel tablosunda her (scenario, key, window) için kayıt var
- [ ] Sanity tablosunda scenario'lar arası **istatistiksel anlamlı** farklar görünüyor
- [ ] Mimicry flood (S5) feature'ları S2 (naive flood) ile **benzer** ama legit ile **farklı** olmalı (mimicry holdout'un mantıklı işleyebileceğinin ön kontrolü)

`git commit -am "Day 13: Tier 2 windowed features + endpoint cost calibration"`

---

## DAY 14 — Week 2 checkpoint

**Hedef:** Geriye dönük tüm Week 2 çıktılarını doğrula. Eksiklik varsa Week
3 başlamadan kapat.

**Toplam süre:** 2-3 saat

### 14.1 End-to-end verification

```bash
# Tüm scenario'lar Database'de
docker compose exec postgres psql -U research -d ddos_research -c "
SELECT id, \"startedAt\", \"endedAt\",
  EXTRACT(EPOCH FROM (\"endedAt\" - \"startedAt\"))/60 AS minutes,
  (SELECT COUNT(*) FROM \"RequestLog\" WHERE \"scenarioId\" = s.id) AS reqs
FROM \"Scenario\" s ORDER BY \"startedAt\";"
```

Tüm 6 scenario + recovery'ler listede, durations ~30 dakika, request counts
beklenen aralıkta.

### 14.2 Class separation visual sanity

```python
python -c "
import pandas as pd
import matplotlib.pyplot as plt
df = pd.read_parquet('analysis/data/features/tier2_features.parquet')
df = df[df['aggregation_type'] == 'ip']

fig, axes = plt.subplots(2, 3, figsize=(15, 8))
for ax, col in zip(axes.flatten(), ['req_rate', 'iat_cv', 'endpoint_entropy',
                                     'endpoint_cost_sum', 'status_4xx_ratio', 'partial_ratio']):
    df.boxplot(column=col, by='majority_label', ax=ax, rot=45)
    ax.set_title(col)
plt.tight_layout()
plt.savefig('analysis/data/features/class_separation_check.png', dpi=120)
print('Saved class_separation_check.png')
"
```

Output PNG'i aç. Her feature için class'lar arası **görsel ayrım** olmalı.
Eğer hiç ayrım yoksa Tier 2 feature engineering'de bug var.

### 14.3 Random-label permutation early sanity

Week 3 Day 18'de full yapacağız ama erken kontrol değerli:

```python
python -c "
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score

df = pd.read_parquet('analysis/data/features/tier2_features.parquet')
df = df.dropna()
df = df[df['aggregation_type'] == 'ip']

X = df[['req_rate', 'iat_cv', 'iat_p95', 'endpoint_entropy',
        'endpoint_cost_sum', 'status_4xx_ratio', 'partial_ratio',
        'ua_entropy', 'sum_db_queries']]
y = df['majority_label']

# Real labels
clf = RandomForestClassifier(n_estimators=50, random_state=42)
real = cross_val_score(clf, X, y, cv=3).mean()

# Permuted labels
y_perm = y.sample(frac=1, random_state=42).reset_index(drop=True)
perm = cross_val_score(clf, X, y_perm, cv=3).mean()

print(f'Real label accuracy: {real:.3f}')
print(f'Permuted label accuracy: {perm:.3f}')
print(f'Diff: {real - perm:.3f}')
print(f'Class baseline (1/n_classes): {1/y.nunique():.3f}')
"
```

**Beklenen:**
- `Real label accuracy`: 0.7-0.95 (modelin gerçekten bir şey öğreniyor)
- `Permuted label accuracy`: 0.20-0.30 (5-class baseline ~%20)
- `Diff` > 0.4 (gerçek sinyal var)

Eğer `Permuted accuracy` > 0.40 ise **data leakage var**. Hangi feature'ın
label-correlated olduğunu bul, çıkar.

### 14.4 Week 2 checkpoint

- [ ] 6 scenario data'sı DB'de, expected counts
- [ ] Connection table dolu, slowloris ayrışıyor
- [ ] Tier 2 features parquet dolu
- [ ] EndpointCostProfile 4 quartile
- [ ] WindowLabel'da (scenario, key, window) tuple'ları
- [ ] Class separation visual sanity (boxplot) — her feature class ayırıyor
- [ ] Random-label permutation: real-perm diff > 0.4

`git commit -am "Day 14: Week 2 complete, all 6 scenarios + Tier 1-2 pipeline + sanity checks"`

---

## Slip risk yönetimi

| Sorun | Olasılık | Mitigasyon |
|---|---|---|
| k6 refactor 2 günde bitmez | Orta | Day 9 sonu deadline; mimicry varyantı atılabilir |
| slowhttptest nginx'e karşı dayanıklı değil | Orta | nginx config tweak; gerekirse real_slowloris v2'ye |
| Overnight run gece çakar | Düşük | Day 11 sonu kontrol; gerekirse subset run |
| Tier 2 aggregation çok yavaş | Orta | dask geçişi, chunked processing |
| Class separation görsel ayrım yok | Yüksek (panic mode trigger) | Week 3 panic-mode pivot, tezde negative result |
| Random-label permutation > 0.4 | Yüksek | Hangi feature leaked? Drop, tekrar |

---

## Hard rules (Week 2)

1. **k6 refactor 2 gün sınırlı.** Day 9 sonu mimicry/credential stuffing
   bitmediyse atlanır.
2. **Overnight run öncesi smoke run zorunlu.** 1-dakika varyantı her
   scenario'yu en az bir kere çalıştırır.
3. **Day 11 sonu data integrity check.** Sabah orchestrator log'una bak,
   her scenario'nun OK bittiğini doğrula.
4. **Random-label permutation testi her model train öncesinde.** Bu Week 2
   Day 14'te erken bir kez, Week 3 Day 18'de full yapılır.
5. **Slowloris çalışmıyorsa Day 10 sonu karar.** Yarın yarın deme.
