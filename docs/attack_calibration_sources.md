# Attack Scenario Parameter Calibration — Verified Sources

> **Status:** Verified version (post citation_verification_log.md doğrulama
> süreci). Önceki versiyondaki LLM-üretilmiş yanlış attribution'lar kaldırıldı,
> doğrulanmış kaynaklarla değiştirildi.
>
> Verification log: `docs/citation_verification_log.md`

Bu doküman k6 attack scenario'larındaki parametrelerin **doğrulanmış kaynak
dayanağını** verir. Tezdeki "Methodology Section: Attack Scenario Calibration"
bölümünün ham referans listesi.

---

## 1. HTTP Flood (Scenarios S2 + S6 mix flood side)

### 1.1 Lab-scale flood rate (200 req/s peak, ~1 req/s per VU)

**Production-scale L7 DDoS context (Cloudflare):**

> Cloudflare. (2025). **DDoS Threat Report 2025 Q1.**
> URL: https://blog.cloudflare.com/ddos-threat-report-for-2025-q1/
> Verified: 2026-05-04

Verified statistics:
- 94% of HTTP DDoS attacks ≤ 1 Mrps (1 million requests/sec)
- 75% of HTTP DDoS attacks ended within 10 minutes
- HTTP DDoS attacks +118% YoY

> Cloudflare. (2025). **DDoS Threat Report 2025 Q4.**
> URL: https://radar.cloudflare.com/reports/ddos-2025-q4
> Verified: 2026-05-06

Verified statistics:
- 47.1 million DDoS attacks in 2025
- HTTP DDoS attack count stable, attack size surged
- Hyper-volumetric campaigns (Aisuru-Kimwolf): peak 205 Mrps

**Botnet existence anchor (Mirai):**

> Antonakakis, M., et al. (2017). **Understanding the Mirai Botnet.**
> *USENIX Security 2017*, pp. 1093-1110.
> URL: https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/antonakakis
> Verified: 2026-05-04

Verified findings:
- ✓ Mirai composed primarily of embedded/IoT devices (PDF p.2 / paper p.1093)
- ✓ Seven-month retrospective analysis (paper p.1093)
- ✓ Peak ~600,000 infections (paper p.1093)
- ✗ **NOT used for per-bot HTTP request rate** (paper does not measure this)

**Bizim k6 parametremiz:**
```javascript
maxVUs: 200, target: 200  // peak 200 req/s aggregate
// Per-VU rate ~1 req/s
```

**Tezdeki gerekçelendirme (revize):**

> "Lab-scale HTTP flood parameters (peak 200 req/s aggregate) represent a
> scaled analog of mid-tier production HTTP DDoS attacks. Cloudflare 2025 Q1
> reports that 94% of HTTP DDoS attacks remained ≤ 1 Mrps with 75% ending
> within 10 minutes [Cloudflare DDoS Threat Report 2025 Q1]. Hyper-volumetric
> campaigns (54-205 Mrps) reported by Cloudflare 2025 Q4 are explicitly out
> of scope at lab dimensions. Botnet-driven L7 attack capability is documented
> in Mirai characterization [Antonakakis et al. 2017, p.1093]; this thesis
> does not transfer per-bot rate values from that work as the original paper
> does not measure HTTP-layer per-bot throughput."

### 1.2 Source IP heterogeneity (overlap'lı IP havuzu)

**Verified industry data:**

> Imperva / Thales Cybersecurity. (2025). **2025 Bad Bot Report.**
> Verified: 2026-05-04

Verified statistics:
- 21% of bot attacks routed through ISPs used residential proxies in 2024 (p.5)
- Residential proxies allow attackers to route malicious traffic through real
  user devices and residential IP addresses, making detection harder based on
  IP reputation alone (p.5)

**Bizim simülasyon kısıtı:** Single host, header-injected sahte IP from
overlap pool (legit ile shared address space).

**Tezdeki Limitations cümlesi:**
> "Source IP heterogeneity is simulated via x-test-client-ip header injection
> from a 50-IP overlap pool with legitimate traffic. This abstracts the
> 21% residential proxy usage observed in production bot traffic
> [Imperva 2025 Bad Bot Report, p.5]; physical network-level distribution
> is not reproduced and is noted in Section [Limitations]."

### 1.3 Endpoint targeting (asymmetric resource consumption)

**OWASP reference (with scope caveat):**

> OWASP Foundation. **OWASP Automated Threats to Web Applications, V1.30.**
> URL: https://owasp.org/www-project-automated-threats-to-web-applications/
> Verified: 2026-05-04

Verified relevant threats:
- **OAT-015 Denial of Service** (p.61 / digital p.67) — application-level
  resource exhaustion. **Scope note:** OAT-015 explicitly EXCLUDES HTTP Flood
  DoS and HTTP Slow DoS ("those protocol and lower layer aspects are covered
  adequately in other taxonomies"). Therefore OAT-015 is used here for the
  *application-resource exhaustion aspect* only; HTTP flood/slow protocol-level
  behavior is anchored to k6/nginx/slowhttptest documentation.

**Bizim k6 parametremiz:**
```javascript
const heavyTerms = ['güvenlik', 'veri', 'analiz', ...];
// Tüm flood'lar /user/search endpoint'ine yöneltiliyor (LIKE query, expensive)
```

**Tezdeki cümle:**

> "Attack traffic concentrates on /user/search endpoint, which exhibits
> expensive backend cost (DB LIKE query) compared to cheap endpoints like
> /health. This reflects the application-resource exhaustion pattern
> documented in OWASP OAT-015 Denial of Service [OWASP Automated Threats
> Handbook V1.30, p.61]."

---

## 2. Low-rate Bot / Scraping (Scenario S3)

### 2.1 Per-source rate (~0.45 req/s)

**Verified industry observation (PRIMARY anchor):**

> Akamai. (2024). **Defend Against Account Abuse in Financial Services.**
> Akamai Security Blog, July 8, 2024.
> URL: https://www.akamai.com/blog/security/defend-against-account-abuse-in-financial-services
> Verified: 2026-05-04

Verified observations from financial services case study:
- Average observed attack rate: ~0.5 requests/sec
- Peak observed attack rate: ~1.3 requests/sec
- Attack characteristics: bot-driven, low-and-slow, attempts to evade
  traditional rate-limiting defenses
- Volume: ~12.7M account abuse requests, ~6.9M bot requests (Q2 2024)

**Caveat:** This is a single financial-services case study, not a global
aggregate. Used as direct empirical anchor for the specific 0.5-1.3 req/s
range observed in production low-and-slow bot attacks.

**Bizim k6 parametremiz:**
```javascript
// 5 VU × 1 req/2.2s = ~2.3 req/s aggregate, ~0.45 req/s per VU
vus: 5, sleep: ~2.2s
```

**Tezdeki cümle:**

> "Per-source low-rate bot scenario rate (~0.45 req/s) is calibrated to the
> lower bound of measured account abuse activity in financial services
> (0.5-1.3 req/s) reported in Akamai security observations
> [Akamai, 2024, https://www.akamai.com/blog/security/defend-against-account-abuse-in-financial-services].
> Per-source rate is below typical configurable rate-limiting thresholds
> (AWS WAF minimum 10 requests per 5-minute evaluation window
> [AWS WAF Developer Guide]) to model rate-limit-aware attackers."

### 2.2 Bot detection feature relevance (NOT numerical rate)

> Doran, D., & Gokhale, S. S. (2011). **Web Robot Detection Techniques:
> Overview and Limitations.** *Data Mining and Knowledge Discovery*,
> 22(1-2), 183-210.
> URL: https://link.springer.com/article/10.1007/s10618-010-0180-z
> Verified: 2026-05-04

Verified findings:
- Web robot detection techniques: syntactical log analysis, traffic pattern
  analysis, analytical learning, Turing test systems (PDF p.5-8)
- Behavioral features for bot detection: request rate, inter-arrival time,
  session duration, image/html ratio, error response %, request arrival
  patterns (PDF p.10-13, p.15-18)
- Hidden/evasive robots: fake UA fields, proxies, robots.txt evasion (p.21-24)

**IMPORTANT — what this paper does NOT provide:**
- ✗ Universal request-per-second threshold (any "0.5-5 req/s" claim is NOT
  in this paper)
- ✗ Specific numerical bot rate ranges

**Use case:** Academic anchor for *which features matter* in bot detection,
not for *numerical parameter calibration*.

**Tezdeki cümle:**

> "Behavioral features (request/query rate, time between requests, session
> duration, resource access patterns) used in this thesis align with
> established Web robot detection literature [Doran & Gokhale 2011,
> p.10-18]. However, that survey does not define universal request-per-second
> thresholds; numerical calibration in this work is anchored to industry
> observations (Section 2.1)."

### 2.3 Narrow endpoint set (low entropy bot signature)

**OWASP reference:**

> OWASP OAT-011 Scraping (p.53 / digital p.59).
> Possible Symptoms (verbatim from handbook): "Unusual request activity for
> selected resources (e.g. high rate, high number, fixed period); unusual
> request rate behavior compared to typical users."

**Bizim k6 parametremiz:**
```javascript
const steadyTerms = ['veri', 'analiz', 'güvenlik']; // sadece 3 term
// Narrow endpoint diversity, sub-rate-limit cadence
```

**Tezdeki cümle:**

> "The low-rate bot scenario uses narrow endpoint diversity (3 search terms,
> 1-2 page values) reflecting the 'selected resources, fixed period' bot
> signature characterized in OWASP OAT-011 Scraping [OWASP Automated Threats
> Handbook V1.30, p.53]."

---

## 3. Credential Stuffing (Scenario S4)

### 3.1 Per-source rate (100 req/s aggregate, ~1 req/s per VU)

**Verified industry context:**

> Akamai. (2026). **State of the Internet — Apps, APIs, and DDoS 2026,
> V12 Issue 01.**
> Verified: 2026-05-06

Verified statistics:
- Broken Authentication: 18.56% of observed API vulnerability issues (p.8)
- Broken Authentication: 21.33% of API incidents per affected customer (p.9)
- Akamai notes weak authentication controls leave APIs vulnerable to
  brute-force and credential stuffing attacks (p.8)
- 61.18% of API attacks involved unauthorized workflows / abnormal activity
  in 2025 (p.6, p.11) — shift toward behavior-based tactics

> Akamai. (2024). **State of the Internet — Digital Fortresses Under Siege,
> V10 Issue 04.**
> Verified: 2026-05-06

Verified statistics:
- 49% increase in web/API attacks Q1 2023 → Q1 2024 (p.3-4)
- 26B+ monthly attacks in June 2024 (up from 14B in early 2023)
- Financial services targeted heavily (55B attacks); credential stuffing
  noted as related abuse vector (p.7)

**OWASP reference:**

> OWASP OAT-008 Credential Stuffing (p.47 / digital p.53).
> Verified verbatim symptoms: "Sequential login attempts with different
> credentials from the same HTTP client (based on IP, User Agent, device,
> fingerprint, patterns in HTTP headers, etc.); High number of failed
> login attempts."

**Bizim k6 parametremiz:**
```javascript
// peak 100 req/s aggregate, 100 VU → ~1 req/s per VU
// random email, random password
```

**Tezdeki cümle:**

> "Credential stuffing scenario produces sequential authentication attempts
> from heterogeneous source IPs/UAs at aggregate ~100 req/s, reflecting the
> behavioral signature characterized in OWASP OAT-008 Credential Stuffing
> [OWASP Automated Threats Handbook V1.30, p.47]. Industry-scale credential
> abuse context: Broken Authentication accounts for 18.56% of observed API
> vulnerability issues [Akamai SOTI Apps APIs DDoS 2026, p.8]."

### 3.2 ~100% 401 response rate (METHODOLOGICAL CLARIFICATION)

**Verified academic measurement of REAL credential stuffing:**

> Thomas, K., et al. (2017). **Data Breaches, Phishing, or Malware?
> Understanding the Risks of Stolen Credentials.** *ACM CCS 2017*,
> pp. 1421-1434.
> URL: https://dl.acm.org/doi/10.1145/3133956.3134067
> Verified: 2026-05-04

Verified statistics:
- Valid credential / password match rate (PDF p.9 / paper p.1429, Table 9):
  - Credential leaks: **6.9% match**
  - Phishing kits: **24.8% match**
  - Keyloggers: **11.9% match**
- Abstract claim: 7-25% of exposed passwords match a victim's Google account
- Pairwise password reuse across 7 leaks: 12-19% (Figure 5, p.1429-1430)

**IMPORTANT — what this paper does NOT provide:**
- ✗ "<5% reuse rate" claim is NOT in this paper
- ✗ The actual measured rate is 7-25% match, NOT <5%

**Methodological honesty (REAL stuffing vs OUR simulation):**

| Type | Match rate | 401 rate |
|---|---|---|
| Real credential stuffing (stolen list) | 7-25% | 75-93% |
| Our simulation (random credentials) | ~0% | ~100% |

Our scenario uses **random** credentials, not stolen lists. This produces
~100% 401 response rate. We deliberately abstract away credential validity
because:
1. The behavioral signature (high 401 rate, /auth/login concentration,
   sequential attempts from heterogeneous sources) is the detection-relevant
   pattern
2. Credential validity is irrelevant to the behavioral feature space

**Tezdeki cümle:**

> "Credential stuffing scenario uses randomly generated credentials, producing
> approximately 100% 401 response rate. This abstracts credential validity:
> real-world credential stuffing using stolen credential lists achieves
> 7-25% match rate (credential leaks 6.9%, keyloggers 11.9%, phishing kits
> 24.8% [Thomas et al. 2017, Section 5.1, Table 9, p.1429]). The simulation
> deliberately focuses on the high-401-ratio behavioral signature
> characteristic of large-scale credential abuse, while abstracting away
> credential validity which does not affect the behavioral detection feature
> space studied in this thesis."

### 3.3 Credential abuse outcome anchor

> Onaolapo, J., Mariconti, E., & Stringhini, G. (2016). **What Happens
> After You Are Pwnd: Understanding the Use of Leaked Webmail Credentials
> in the Wild.** *ACM IMC 2016*, pp. 65-79.
> URL: https://dl.acm.org/doi/10.1145/2987443.2987475
> Verified: 2026-05-04

Verified findings (controlled honey-account experiment):
- 100 Gmail honey accounts, 7-month monitoring (PDF p.1 / paper p.65)
- 326 unique attacker accesses recorded
- 90/100 accounts received accesses
- 36/100 accounts hijacked (password changed)
- Attacker taxonomy: Curious, Gold Digger, Spammer, Hijacker (p.6-7)
- Stealth/evasion: malware-based attackers used Tor, hid system config,
  attempted location-based evasion (p.8-10)

**IMPORTANT limitations:**
- ✗ Paper does NOT provide credential-stuffing success rate
- ✗ Paper does NOT provide "<5% reuse rate"
- 36/100 hijacking is honey-account experiment, NOT global statistic

**Use case:** Anchor for the claim that leaked credentials are *actively
exploited* and that attackers attempt evasion/stealth. NOT for numerical
rate calibration.

**Tezdeki cümle:**

> "Leaked credentials are actively exploited in the wild; controlled
> honey-account experiments document active attacker access patterns
> including stealth and evasion attempts [Onaolapo et al. 2016,
> Section 4-5, p.70-74]. This justifies including credential abuse as
> a realistic attack scenario in the threat model."

---

## 4. Real Slowloris (Scenario S6)

### 4.1 Connection count and timing parameters

**PRIMARY anchor — tool documentation:**

> Shekyan, S. **slowhttptest** — Application Layer DoS attack simulator.
> URL: https://github.com/shekyan/slowhttptest
> Verified: 2026-05-03

Verified default parameters (from README Usage section):
- `-c` (number of connections): default 50, examples up to 1000
- `-i` (interval between followup data): default 10 seconds
- `-r` (connections per second): default 50
- `-x` (max length of followup data field): 32 bytes
- Test duration default: 240 seconds

Attack mode flags (verified):
- `-H` → slowloris mode (incomplete header)
- `-B` → slow message body mode (RUDY)
- `-X` → slow read mode (TCP receive window manipulation)

**Server-side defaults (nginx):**

> nginx Documentation. **HTTP core module.**
> URL: https://nginx.org/en/docs/http/ngx_http_core_module.html
> Verified: 2026-05-03

Verified defaults:
- `client_header_timeout`: 60s (returns 408 on timeout)
- `client_body_timeout`: 60s (returns 408 on timeout)
- `keepalive_timeout`: 75s
- `worker_connections`: 512 (per-worker default)

**Bizim k6 parametremiz (slowhttptest):**
```bash
slowhttptest -c 500 -H -i 10 -r 50 -t GET
```

**Tezdeki cümle:**

> "Real slowloris attack uses slowhttptest with 500 concurrent connections
> at 10s header drip interval, parameters within the documented range of
> slowhttptest tool defaults (-c 50 to -c 1000, -i 10s)
> [Shekyan, slowhttptest GitHub README]. Server-side, nginx is configured
> with production-realistic timeouts (client_header_timeout=60s,
> client_body_timeout=60s) per nginx core module documentation
> [nginx HTTP core module, https://nginx.org/en/docs/http/ngx_http_core_module.html]
> to allow the slowloris signature (status 408 timeout) to develop rather
> than triggering early connection drops."

### 4.2 Historical / context reference

> Hansen, R. ("RSnake") (2009). **Slowloris HTTP DoS.** Original tool release.
> Original site (now defunct): http://ha.ckers.org/slowloris/

Note: Used only as historical context for the slowloris attack class. Tool
parameters anchor to slowhttptest documentation.

> ~~Cambiaso, E., Papaleo, G., Chiola, G., & Aiello, M. (2013). "Slow DoS
> Attacks: Definition and Categorisation." *International Journal of Trust
> Management in Computing and Communications.*~~
>
> **REMOVED** from citation chain due to publisher paywall and inaccessibility.
> Slow-DoS taxonomy is adequately documented in slowhttptest tool documentation
> (`-H`, `-B`, `-X` flags map to slowloris, slow-POST, slow-read).

---

## 5. Slow-POST / RUDY (Scenario S6 alt)

### 5.1 Body drip interval: 110s

**Anchor — tool documentation:**

> slowhttptest -B mode (slow message body), per Shekyan slowhttptest README
> (verified 2026-05-03).

Verified slow-POST example from README:
```bash
slowhttptest -c 1000 -B -g -o my_body_stats -i 110 -r 200 -s 8192 -t FAKEVERB \
  -u https://server/loginform.html -x 10 -p 3
```

**Bizim k6 parametremiz:**
```bash
slowhttptest -c 500 -B -i 110 -r 50 -t POST
```

**Tezdeki cümle:**

> "Slow-POST (RUDY) parameters (500 concurrent connections, 110s body drip
> interval) follow slowhttptest -B mode documented examples
> [Shekyan, slowhttptest GitHub README]."

---

## 6. Mimicry Flood (Scenario S5 — HOLDOUT)

### 6.1 Conceptual basis (academic)

> Wagner, D., & Soto, P. (2002). **Mimicry Attacks on Host-based Intrusion
> Detection Systems.** *ACM CCS 2002*, pp. 255-264.
> URL: https://dl.acm.org/doi/10.1145/586110.586145
> Verified: 2026-05-04

Verified findings:
- Paper introduces the term "mimicry attack" (PDF p.4 / paper p.258)
- Mimicry attack allows sophisticated attacker to cloak intrusion and
  evade IDS detection (p.255-256)
- Formalized using system-call traces and host-based IDS (pH IDS) context
  (p.4-8)
- Experimental evasion against pH host-based IDS demonstrated (PDF p.8)

**Important context note:** Wagner & Soto's mimicry is **dynamic**
(iterative system-call modification matching normal traces), not "static."
HTTP-layer transfer is **conceptual**, not direct empirical.

> Fogla, P., Sharif, M., Perdisci, R., et al. (2006). **Polymorphic
> Blending Attacks.** *USENIX Security 2006*, pp. 241-256.
> URL: https://www.usenix.org/legacy/event/sec06/tech/full_papers/fogla/fogla.pdf
> Verified: 2026-05-04

Verified findings:
- Polymorphic blending attacks evade byte-frequency-based network anomaly
  IDS (PAYL) (PDF p.1 / paper p.241)
- Blending attacks transform malicious payload to match normal traffic
  statistical profile (PDF p.3-4 / paper p.243-244)
- Authors describe blending attacks as a subclass of mimicry attacks
  (PDF p.1)
- Experimental evasion against PAYL using HTTP traffic data (PDF p.10-13)

**Important limitation:** Fogla focuses on **payload byte/n-gram statistics**,
not HTTP metadata (headers, endpoint paths, request intervals, user session
behavior). HTTP-metadata-level mimicry is **conceptual transfer**, not
direct empirical evidence from this paper.

### 6.2 HTTP-layer empirical anchor (PRIMARY for mimicry)

> Imperva / Thales Cybersecurity. (2025). **2025 Bad Bot Report.**
> Verified: 2026-05-04

Verified statistics directly relevant to mimicry:
- **21% of bot attacks routed through ISPs used residential proxies** in 2024
  (p.5 / Bot Evasion Tactics) — supports our IP overlap design
- **46% of bad bot attacks declared themselves as Chrome** (p.17 / Browser
  Impersonation) — supports our sophisticated UA pool design
- Mobile Safari: 17%, Mobile Chrome: 14% (p.17)
- Bot evasion tactics (p.15-16): fake browser identity, residential proxies,
  privacy tools, headless browsers, AI-assisted scripting, polymorphic bots
- Account Takeover attacks +40% in 2024, +54% since 2022 (p.18-20)
- Advanced + moderate bot attacks: 55% of all bot attacks in 2024 (p.4)

### 6.3 OWASP HTTP-layer threat anchor

> OWASP OAT-008 Credential Stuffing (p.47 / digital p.53).
> Suggested countermeasure (verbatim): "Consider identifying and restricting
> automated usage by fingerprinting the User Agent for its unique
> characteristics."
>
> Reverse implication: attackers do attempt to **avoid** UA fingerprinting,
> typically by impersonating common browsers and rotating UA strings.

### 6.4 Akamai mimicry-related observations

> Akamai SOTI Apps APIs and DDoS 2026 V12 Issue 01:
> "Bots, scripted clients, headless browsers, and automation frameworks can
> maintain state, adapt behavior, and blend into normal traffic patterns."
> (p.4-5, "The economics of modern internet attacks")

**Bizim k6 parametremiz:**
```javascript
// UA: SOPHISTICATED_ATTACKER_AGENTS = LEGIT_AGENTS (özdeş havuz)
// IP: getIpPool('sophisticated') = legit ile overlap
// Token reuse: sticky session
```

**Tezdeki cümle:**

> "The mimicry flood scenario operationalizes a non-iterative HTTP-layer
> mimicry attack: surface features (User-Agent distribution, source IP
> space) are sampled from the legitimate user pool, while attack-level
> request rate is preserved. This design reflects measured bot evasion
> tactics: 21% of bot attacks use residential proxies (IP-space mimicry)
> and 46% impersonate Chrome browser (UA mimicry) [Imperva 2025 Bad Bot
> Report, p.5, p.17]. Akamai SOTI 2026 documents that 'bots, scripted
> clients, headless browsers, and automation frameworks can maintain state,
> adapt behavior, and blend into normal traffic patterns'
> [Akamai SOTI Apps APIs and DDoS 2026 V12-01, p.4-5].
>
> The conceptual mimicry framework follows seminal academic work on
> mimicry attacks against intrusion detection systems
> [Wagner & Soto 2002, p.255-262] and statistical traffic blending
> [Fogla et al. 2006, p.241-244]; the HTTP-metadata-layer adaptation
> (vs. system-call or payload-byte-level original contexts) is
> acknowledged as conceptual transfer.
>
> Iterative, adaptive adversaries (where the attacker monitors detection
> feedback and evolves) are explicitly out of scope and listed as future
> work."

---

## 7. Final citation chain (post-verification)

### Tool documentation (highest confidence)
- ✓ Shekyan, slowhttptest GitHub README
- ✓ nginx HTTP core module documentation
- ✓ AWS WAF Developer Guide (rate-based rules)
- ✓ Cloudflare WAF Rate Limiting documentation (with note: no universal default)
- ✓ k6 / Grafana load testing documentation

### Industry reports (verified PDFs/blogs)
- ✓ Akamai SOTI Apps APIs and DDoS 2026 V12 Issue 01
- ✓ Akamai SOTI Digital Fortresses 2024 V10 Issue 04
- ✓ Akamai Account Abuse blog (July 2024) — direct empirical 0.5-1.3 req/s anchor
- ✓ Cloudflare DDoS Threat Report 2025 Q1
- ✓ Cloudflare DDoS Threat Report 2025 Q4
- ✓ Imperva 2025 Bad Bot Report — direct empirical mimicry anchor (21% RP, 46% Chrome)

### Standards (highest confidence)
- ✓ OWASP Automated Threats Handbook V1.30
  - OAT-008 Credential Stuffing (p.47)
  - OAT-011 Scraping (p.53)
  - OAT-014 Vulnerability Scanning (p.59)
  - OAT-015 Denial of Service (p.61, with HTTP scope caveat)
- ✓ RFC 9110 (HTTP Semantics) — optional, only if discussing HTTP auth flow

### Academic (verified, used sparingly)
- ✓ Antonakakis et al. 2017 (Mirai botnet existence/scale only, NOT per-bot rate)
- ✓ Wagner & Soto 2002 (mimicry attack conceptual framework, host-IDS context)
- ✓ Fogla et al. 2006 (statistical blending conceptual framework, payload-level context)
- ✓ Doran & Gokhale 2011 (bot detection feature relevance, NOT numerical rates)
- ✓ Thomas et al. 2017 (stolen credential match rates 7-25%, hijacking risk)
- ✓ Onaolapo et al. 2016 (credential exploitation evidence, honey-account context)

### Removed from citation chain
- ✗ ~~Cambiaso et al. 2013~~ — paywalled, inaccessible. Replaced by slowhttptest tool docs.
- ✗ ~~Stevanovic et al. 2014~~ — claim attribution couldn't be verified, removed.

---

## 8. Bibtex collection (verified entries)

```bibtex
@inproceedings{antonakakis2017mirai,
  title     = {Understanding the {Mirai} Botnet},
  author    = {Antonakakis, Manos and April, Tim and Bailey, Michael and
               Bernhard, Matt and Bursztein, Elie and Cochran, Jaime and
               Durumeric, Zakir and Halderman, J. Alex and Invernizzi, Luca
               and Kallitsis, Michalis and others},
  booktitle = {26th USENIX Security Symposium (USENIX Security 17)},
  pages     = {1093--1110},
  year      = {2017},
  publisher = {USENIX Association},
  url       = {https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/antonakakis}
}

@inproceedings{wagner2002mimicry,
  title     = {Mimicry Attacks on Host-based Intrusion Detection Systems},
  author    = {Wagner, David and Soto, Paolo},
  booktitle = {Proceedings of the 9th ACM Conference on Computer and
               Communications Security (CCS '02)},
  pages     = {255--264},
  year      = {2002},
  doi       = {10.1145/586110.586145}
}

@inproceedings{fogla2006polymorphic,
  title     = {Polymorphic Blending Attacks},
  author    = {Fogla, Prahlad and Sharif, Monirul and Perdisci, Roberto
               and Kolesnikov, Oleg and Lee, Wenke},
  booktitle = {15th USENIX Security Symposium (USENIX Security '06)},
  pages     = {241--256},
  year      = {2006},
  url       = {https://www.usenix.org/legacy/event/sec06/tech/full_papers/fogla/fogla.pdf}
}

@article{doran2011robot,
  title   = {Web Robot Detection Techniques: Overview and Limitations},
  author  = {Doran, Derek and Gokhale, Swapna S.},
  journal = {Data Mining and Knowledge Discovery},
  volume  = {22},
  number  = {1-2},
  pages   = {183--210},
  year    = {2011},
  publisher = {Springer},
  doi     = {10.1007/s10618-010-0180-z}
}

@inproceedings{thomas2017stolen,
  title     = {Data Breaches, Phishing, or Malware? {Understanding} the
               Risks of Stolen Credentials},
  author    = {Thomas, Kurt and Li, Frank and Zand, Ali and Barrett,
               Jacob and Ranieri, Juri and Invernizzi, Luca and Markov,
               Yarik and Comanescu, Oxana and Eranti, Vijay and
               Moscicki, Angelika and Margolis, Daniel and Paxson,
               Vern and Bursztein, Elie},
  booktitle = {Proceedings of the 2017 ACM SIGSAC Conference on Computer
               and Communications Security (CCS '17)},
  pages     = {1421--1434},
  year      = {2017},
  doi       = {10.1145/3133956.3134067}
}

@inproceedings{onaolapo2016pwnd,
  title     = {What Happens After You Are Pwnd: Understanding the Use of
               Leaked Webmail Credentials in the Wild},
  author    = {Onaolapo, Jeremiah and Mariconti, Enrico and Stringhini,
               Gianluca},
  booktitle = {Proceedings of the 2016 Internet Measurement Conference
               (IMC '16)},
  pages     = {65--79},
  year      = {2016},
  doi       = {10.1145/2987443.2987475}
}

@misc{owasp_oat_handbook,
  title        = {{OWASP} Automated Threats to Web Applications --- Handbook},
  author       = {{OWASP Foundation}},
  edition      = {V1.30},
  url          = {https://owasp.org/www-project-automated-threats-to-web-applications/}
}

@misc{akamai_soti_apps_apis_ddos_2026,
  title        = {State of the Internet --- Apps, {APIs}, and {DDoS} 2026:
                  Prepare for the Convergence Crisis},
  author       = {{Akamai Technologies}},
  year         = {2026},
  edition      = {V12 Issue 01},
  publisher    = {Akamai Technologies, Inc.}
}

@misc{akamai_soti_digital_fortresses_2024,
  title        = {State of the Internet --- Digital Fortresses Under Siege:
                  Threats to Modern Application Architectures},
  author       = {{Akamai Technologies}},
  year         = {2024},
  edition      = {V10 Issue 04},
  publisher    = {Akamai Technologies, Inc.}
}

@misc{akamai_account_abuse_blog_2024,
  title        = {Defend Against Account Abuse in Financial Services},
  author       = {{Akamai Technologies}},
  year         = {2024},
  month        = {7},
  url          = {https://www.akamai.com/blog/security/defend-against-account-abuse-in-financial-services}
}

@misc{cloudflare_ddos_2025_q1,
  title        = {{DDoS} Threat Report for 2025 Q1},
  author       = {{Cloudflare, Inc.}},
  year         = {2025},
  url          = {https://blog.cloudflare.com/ddos-threat-report-for-2025-q1/}
}

@misc{cloudflare_ddos_2025_q4,
  title        = {{DDoS} Threat Report for 2025 Q4},
  author       = {{Cloudflare, Inc.}},
  year         = {2026},
  month        = {2},
  url          = {https://radar.cloudflare.com/reports/ddos-2025-q4}
}

@misc{imperva_bad_bot_2025,
  title        = {2025 Bad Bot Report},
  author       = {{Imperva} and {Thales Cybersecurity}},
  year         = {2025},
  url          = {https://www.imperva.com/resources/resource-library/reports/}
}

@misc{shekyan_slowhttptest,
  title  = {slowhttptest --- Application Layer {DoS} attack simulator},
  author = {Shekyan, Sergey},
  url    = {https://github.com/shekyan/slowhttptest}
}

@misc{nginx_http_core,
  title = {nginx Documentation: {HTTP} core module},
  url   = {https://nginx.org/en/docs/http/ngx_http_core_module.html}
}

@misc{aws_waf_rate_based,
  title  = {{AWS WAF} Developer Guide: Rate-based rule statement},
  author = {{Amazon Web Services}},
  url    = {https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html}
}

@misc{cloudflare_waf_rate_limiting,
  title  = {Cloudflare {WAF} --- Rate Limiting Rules},
  author = {{Cloudflare, Inc.}},
  url    = {https://developers.cloudflare.com/waf/rate-limiting-rules/}
}
```

---

## 9. Methodology paragraph for thesis

> "Attack scenario parameter justification was developed via a multi-source
> verification protocol. Each parameter is anchored to one or more verified
> sources spanning four categories: (1) tool documentation
> (slowhttptest, nginx, k6, AWS WAF, Cloudflare WAF), (2) verified industry
> reports (Akamai SOTI 2024-2026, Cloudflare DDoS Threat Reports 2025 Q1
> and Q4, Imperva 2025 Bad Bot Report, Akamai Account Abuse blog),
> (3) standards documentation (OWASP Automated Threats Handbook V1.30),
> and (4) peer-reviewed academic literature used sparingly for conceptual
> framework anchoring (Antonakakis et al. 2017 for botnet existence;
> Wagner & Soto 2002 and Fogla et al. 2006 for mimicry framework;
> Doran & Gokhale 2011 for bot detection feature relevance; Thomas et al.
> 2017 and Onaolapo et al. 2016 for credential abuse outcome evidence).
>
> All citations were independently verified against primary sources during
> methodology development. The verification process identified and corrected
> several attribution errors generated by initial AI-assisted citation
> drafting (e.g., per-bot HTTP request rates incorrectly attributed to
> Antonakakis et al. 2017 which measures scan bandwidth not HTTP flood
> rate; '0.5-5 req/s' rate range incorrectly attributed to Doran & Gokhale
> 2011 which does not provide numerical thresholds; '<5% credential reuse
> rate' incorrectly attributed to Onaolapo et al. 2016 which measures
> honey-account hijacking not global reuse). The full verification log is
> provided in `docs/citation_verification_log.md` as supplementary material."

---

## 10. Methodological honesty notes

Bu çalışmada **dürüstçe kabul edilen** sınırlar:

1. **Per-bot HTTP flood rate** için doğrudan akademik measurement yok.
   Lab parametresi (200 req/s aggregate) Cloudflare'in gözlemlediği
   ≤1 Mrps tipik attack'larının scaled-down lab analog'u olarak
   gerekçelendirildi.

2. **Credential stuffing** scenario random credentials kullanır
   (~100% 401), real stolen-list stuffing'in 7-25% match rate'i
   simulate edilmedi. Behavioral signature focused experiment.

3. **Source IP heterogeneity** header injection ile simulated. Real
   network-level distribution (residential proxies — Imperva 2025 21%
   measured) lab dimensions'da yok.

4. **Slow-DoS taxonomy** için Cambiaso 2013 paywall nedeniyle
   accessible değil; slowhttptest tool documentation kullanıldı.

5. **Mimicry attack** static (non-iterative); iterative ML-based
   adaptive adversary explicitly out of scope (future work).

6. **Modern HTTP/2 attack vectors** (Rapid Reset CVE-2023-44487) scope
   dışı; HTTP/1.1 only experiments.
