# Methodology — Draft (Week 1 sonu)

## 1. System Architecture

### 1.1 Application Layer
- NestJS 11 (TypeScript), JWT-based authentication
- Prisma 6 ORM with PostgreSQL 16
- Endpoint diversity: 4 cost classes (cheap: /health,/ping;
  medium: /metrics/users/count, /user/profile;
  expensive: /metrics/reports/login-stats; very expensive: /user/search)

### 1.2 Reverse Proxy
- nginx 1.27 in front of NestJS
- Custom log_format `ddos_research` capturing 35+ fields per request
  including upstream timing, connection ID, TLS metadata
- Production-realistic timeout settings:
  client_header_timeout=60s, client_body_timeout=60s,
  keepalive_timeout=75s

### 1.3 Database
- Local PostgreSQL 16 in Docker container
- Migration handled via `prisma db push` (research workflow);
  `prisma/migrations/` directory inherited from parent project, not used
- Schema: 11 tables — RequestLog, Connection, BehavioralSession,
  WindowLabel, EndpointCostProfile, Scenario, CalibrationBaseline plus
  inherited User/LoginAttempt/IpBlock

### 1.4 Backend Cost Instrumentation
- Prisma `$on('query')` hook captures dbQueryCount and dbTotalTimeMs
  per request via AsyncLocalStorage
- `process.cpuUsage()` measures cpu time
- Global NestJS interceptor sets X-* response headers consumed by nginx
  access log
- Application-level rate limiting (IpBlock) deliberately disabled to
  isolate behavioral detection signal from rate-limit-induced traffic
  distortions

## 2. Calibration Datasets (multi-trace, two-axis cross-validation)

Bu çalışmada üç bağımsız ITA Internet Traffic Archive trace'i, **iki ayrı
cross-validation eksenini** doldurmak için kullanılır.

### 2.1 NASA HTTP Traces (Jul + Aug 1995) — primary + temporal cross-val
- Source: ITA Internet Traffic Archive
- NASA Jul95: ~1.9M requests, 81,967 unique hosts
- NASA Aug95: ~1.6M requests, 75,038 unique hosts
- Public-facing space agency website (single-domain content site)
- Used for: per-session IAT, session length, Markov transitions, Zipf
- **Temporal cross-validation** (Jul vs Aug): same institution, consecutive
  months, full host info on both

### 2.2 ClarkNet HTTP Traces (Aug 28 + Sep 4 1995) — institutional cross-val
- Source: ITA Internet Traffic Archive
- ClarkNet Aug28: ~1.65M requests, 90,497 unique hosts
- ClarkNet Sep4: ~1.67M requests, 94,757 unique hosts
- Commercial Internet service provider (multi-site gateway traffic)
- Used for: per-session IAT, session length, Markov transitions, Zipf
- **Institutional cross-validation vs NASA**: different institution, different
  user base, different content context, full host info preserved

### 2.3 Calgary HTTP Trace (Oct 1994 – Sep 1995) — path-level cross-trace
- Source: ITA Internet Traffic Archive
- ~726K requests, ~10 months
- University of Calgary
- **Anonymization caveat:** ITA archive reduced all client hosts to two
  aggregated values (local/remote). Per-user session segmentation,
  per-session IAT, and session-aware Markov transitions are precluded on
  this trace.
- Used for: path-level features only (Zipf endpoint popularity, method/
  status distribution)
- **Path-level institutional cross-trace** vs NASA and ClarkNet for
  endpoint popularity validation

### 2.4 Two-axis cross-validation rationale
The five traces span two orthogonal cross-validation axes:

| Axis | Pair | Purpose |
|---|---|---|
| Temporal (NASA) | Jul95 vs Aug95 | Same institution, different month |
| Temporal (ClarkNet) | Aug28 vs Sep4 | Same institution, different week |
| **Institutional (full)** | **NASA vs ClarkNet** | Different institution, full session-level analysis |
| Path-level institutional | NASA / ClarkNet vs Calgary | Path-popularity only |

This two-axis design separates **temporal stability** (same context, different
time) from **institutional generalizability** (different context). Parameters
that survive both axes are candidates for transferable structural priors;
parameters that vary across axes are context-dependent and require
deployment-specific re-parameterization.

### 2.5 Empirical structural-vs-context findings

Three independent measurements consistently support the structural-prior
framing (full report: `analysis/data/baselines/consistency_report.txt`):

**Inter-arrival time (lognormal):**
| Trace | μ_log | σ_log | mean (s) | median (s) |
|---|---|---|---|---|
| NASA Jul95 | 2.379 | 1.747 | 55.52 | 9.00 |
| NASA Aug95 | 2.159 | 1.712 | 46.94 | 7.00 |
| ClarkNet Aug28 | 1.820 | 1.604 | 35.73 | 5.00 |
| ClarkNet Sep4 | 1.828 | 1.601 | 35.86 | 5.00 |

- **σ_log invariant** (range 1.60–1.75, ~9% spread across institutions and
  months) → structural prior, transferable
- **μ_log context-dependent** (NASA avg 2.27 vs ClarkNet avg 1.82, 19.6%
  inter-institutional difference; intra-institutional <10%)

**Endpoint popularity (Zipf):**
| Trace | α | Unique paths | Top-10 share |
|---|---|---|---|
| NASA Jul95 | 1.25 | 7,221 | 30.7% |
| NASA Aug95 | 1.25 | 6,525 | 36.1% |
| Calgary | 0.84 | 8,367 | 29.1% |
| ClarkNet Aug28 | 0.94 | 25,222 | 10.0% |
| ClarkNet Sep4 | 0.97 | 24,257 | 10.6% |

- **Power-law shape universal** (5/5 traces fit Zipf)
- **α value context-dependent** (NASA single-domain → steeper α=1.25;
  ClarkNet ISP → flatter α=0.95; Calgary → α=0.84)

**Markov transition matrices:**
- Intra-institutional pairwise mean |diff|: 0.013
- Inter-institutional pairwise mean |diff|: 0.080
- **6× ratio** between intra- and inter-institutional variation
- **Same categorical structure** (html/image/cgi/etc.) applies universally;
  transition probabilities themselves are institution-specific

**Session-level metrics:**
| Trace | Sessions | Mean req/session | Median | Bounce rate |
|---|---|---|---|---|
| NASA Jul95 | 162,716 | 11.62 | 7 | 9.93% |
| NASA Aug95 | 143,729 | 10.92 | 7 | 9.63% |
| ClarkNet Aug28 | 139,690 | 11.84 | 6 | 20.69% |
| ClarkNet Sep4 | 144,195 | 11.60 | 6 | 22.42% |

- **Active session length** (mean ~11.5, median 6–7) structurally similar
  across institutions
- **Bounce rate** 2.2× different (NASA ~10% vs ClarkNet ~22%) — reflects
  single-domain vs gateway context

### 2.6 Methodological framing for thesis defense
NASA and ClarkNet are pre-AJAX, pre-mobile, pre-CDN. They are NOT used to
model modern API-driven SPA traffic patterns or HTTP/2 multiplexing.
Calibration use is restricted to **distribution shapes** (lognormal,
Zipf-power-law, transition-matrix structure, geometric session length) which
derive from human cognitive limits and statistical mechanics that have not
changed since 1995. **Specific numerical parameters** (μ_log, α, exact
transition probabilities, bounce rate) are explicitly identified as
context-dependent and re-parameterized for the test NestJS application via
sensitivity analysis. External attack-trace validation is performed against
CIC-DDoS2019 (Week 3 Day 20).

### 2.7 Methodological adaptation log
During Calgary trace inspection, ITA archive anonymization (all hosts →
local/remote) was discovered, precluding session-level analysis on that
trace. The original two-trace plan (NASA + Calgary) was adapted to a
five-trace design with two cross-validation axes. ClarkNet was added as
session-capable institutional cross-validation; Calgary retained for
path-level cross-trace. This adaptation is documented for transparency
rather than retrospectively justified.

[Day 11+ traffic generation, Tier 1-3 features, detection model — Week 2-4'te
eklenecek]

## 3. Threat Model
[Week 2 k6 refactor sonrasında doldurulacak]

## 4. Feature Engineering
[Week 2 Tier 2 pipeline sonrasında doldurulacak]