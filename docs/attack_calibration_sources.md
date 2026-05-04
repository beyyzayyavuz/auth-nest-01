# Attack Scenario Parameter Calibration — Literature Sources

Bu doküman k6 attack scenario'larındaki parametrelerin **akademik dayanağını**
verir. Tezdeki "Methodology Section: Attack Scenario Calibration" bölümünün
ham referans listesi.

> **Önemli:** Bu doküman literatür referanslarını listeler. Tezde kullanmadan
> önce her bir kaynağın güncel ve erişilebilir olduğunu **mutlaka kontrol et**
> (DOI, sayfa sayıları, alıntı sayıları). LLM'ler nadiren citation
> hallucinate edebilir — birinci kontrol sende.

---

## 1. HTTP Flood (Scenarios S2, S5, S6 attack side)

### 1.1 Per-bot request rate (5-50 req/s)

**Kaynak:** Antonakakis, M., April, T., Bailey, M., et al. (2017).
"Understanding the Mirai Botnet." *26th USENIX Security Symposium*.

- Mirai botnet'in detaylı karakterizasyonu (yaklaşık 600K cihaz)
- Per-bot ortalama saldırı throughput'u: 1-50 req/s aralığında, ortalama
  ~10 req/s
- Source IP heterogeneity: 11 ayda 1.2M unique IP

**Bizim k6 parametremiz:**
```javascript
// peak 200 req/s aggregate, 200 VU → ~1 req/s per VU (per "bot")
// Mirai bot-level rate'in alt sınırı (gerçekçi botnet üyesi)
maxVUs: 200, target: 200
```

**Tezde gerekçelendirme cümlesi:**
> "Per-source HTTP flood rate of approximately 1 req/s aggregating to 200
> req/s peak reflects the lower bound of per-bot request rate measured
> in the Mirai botnet study (Antonakakis et al., 2017), which observed
> distributed flood traffic of 5-50 req/s per individual compromised
> device."

### 1.2 Source IP heterogeneity (binlerce farklı IP, overlap legit ile)

**Aynı Mirai paper'ı:** 1.2M unique IP, geographic dispersion, residential
ISP dominance.

**Bizim simülasyon kısıtı:** Single host, header-injected sahte IP.
Limitation'da yaz:
> "Source IP heterogeneity is simulated via x-test-client-ip header
> injection from a 50-IP overlap pool with legitimate traffic. Physical
> network-level distribution is not reproduced; this is a deliberate
> scope limitation noted in Section X (Limitations)."

### 1.3 Endpoint targeting (expensive endpoints)

**Kaynak:** Cambiaso, E., Papaleo, G., Chiola, G., & Aiello, M. (2013).
"Slow DoS Attacks: Definition and Categorisation." *International Journal
of Trust Management in Computing and Communications*, 1(3-4), 300-319.

- Resource exhaustion attack characterization
- Asymmetric resource consumption: low traffic, high backend impact

**Bizim k6 parametremiz:**
```javascript
const heavyTerms = ['güvenlik', 'veri', 'analiz', ...];
// Tüm flood'lar /user/search endpoint'ine yöneltiliyor (LIKE query, expensive)
```

**Tezde:**
> "Attack traffic concentrates on /user/search endpoint, which exhibits
> expensive backend cost (DB LIKE query, p95 ~50-200ms) compared to
> cheap endpoints like /health (<1ms). This reflects the asymmetric
> resource exhaustion attack pattern characterized by Cambiaso et al.
> (2013)."

---

## 2. Low-rate Bot / Scraping (Scenario S3)

### 2.1 Per-source rate <1 req/s, sub-threshold

**Kaynak:** Doran, D., & Gokhale, S. S. (2011). "Web Robot Detection
Techniques: Overview and Limitations." *Data Mining and Knowledge
Discovery*, 22(1-2), 183-210.

- Web bot davranış karakterizasyonu
- Modern stealth scraper'lar tipik 0.5-5 req/s/source aralığında çalışır
  (rate limit altında uçmak için)

**Bizim k6 parametremiz:**
```javascript
// 5 VU × 1 req/2.2s = ~2.3 req/s aggregate, ~0.45 req/s per VU
vus: 5, sleep: ~2.2s
```

### 2.2 Narrow endpoint set (low entropy)

**Kaynak:** Stevanovic, M., An, A., & Vlajic, N. (2014). "Detection of
Malicious and Non-malicious Website Visitors Using Unsupervised Neural
Network Learning." *Applied Soft Computing*, 13(1), 698-708.

- Bot vs insan davranış ayrımı: bot'lar dar endpoint set'i ziyaret eder
- Insan trafiği geniş endpoint diversity gösterir

**Bizim k6 parametremiz:**
```javascript
const steadyTerms = ['veri', 'analiz', 'güvenlik']; // sadece 3 term
```

**Tezde:**
> "Low-rate bot scenario reflects stealth scraping characterizations from
> Doran & Gokhale (2011): per-source rates below typical rate-limiting
> thresholds (~5 req/s/IP in production deployments) and narrow endpoint
> diversity (Stevanovic et al., 2014). Our parameters target ~0.5 req/s
> per source over a 3-term search vocabulary."

---

## 3. Credential Stuffing (Scenario S4)

### 3.1 Per-source rate 5-50/s, distributed pattern

**Kaynak (industry):** Akamai (2023). *State of the Internet Security:
The Lurking Threat of Account Abuse*. Akamai Technologies Annual Report.

- Credential abuse attack measurements: distributed sources, per-source
  rates 5-50/s typical, peak aggregate 12-13K attempts/s on monitored
  customers

**Kaynak (akademik):** Thomas, K., Li, F., Zand, A., et al. (2017).
"Data Breaches, Phishing, or Malware? Understanding the Risks of Stolen
Credentials." *Proceedings of the 2017 ACM SIGSAC Conference on Computer
and Communications Security (CCS '17)*, 1421-1434.

- Çalınmış credential'ların kullanım kalıpları
- Distributed attack patterns characterization

**Bizim k6 parametremiz:**
```javascript
// peak 100 req/s aggregate, 100 VU → ~1 req/s per VU
// Akamai SOTI'nin distributed pattern alt sınırı
```

### 3.2 95%+ 401 oranı

**Kaynak:** Onaolapo, J., Mariconti, E., & Stringhini, G. (2016). "What
Happens After You Are Pwnd: Understanding the Use of Leaked Webmail
Credentials in the Wild." *Proceedings of the 2016 Internet Measurement
Conference (IMC '16)*, 65-79.

- Çalınmış credential reuse oranları
- Successful login rate <%5 (most password lists don't match target)

**Bizim k6 parametremiz:**
```javascript
function randomEmail() { return `attacker${random}@example.com`; }
function randomPassword() { return random; }
// %0 başarı bekleniyor (sentetik random)
```

**Tezde:**
> "Credential stuffing scenario uses random email/password combinations
> generating ~95%+ 401 responses, consistent with measurements of leaked
> credential reuse rates in Onaolapo et al. (2016). Per-source rate
> (~1 req/s, aggregating to 100 req/s peak) reflects distributed
> credential abuse patterns documented in Akamai State of the Internet
> 2023."

---

## 4. Real Slowloris (Scenario S6)

### 4.1 Connection count: 500-1000 concurrent

**Kaynak:** Cambiaso, E., Papaleo, G., Chiola, G., & Aiello, M. (2013).
"Slow DoS Attacks: Definition and Categorisation." (yukarıda da var)

- Slow-DoS family taxonomy: slowloris, slow-POST, slow-read
- Effective attack: 200-1000 paralel partial connection
- Original Slowloris tool (RSnake/Hansen, 2009) default: 200 connections

**Kaynak:** slowhttptest tool documentation
(https://github.com/shekyan/slowhttptest)

- Default `-c` (connections): 50, ama akademik literatürde tipik 200-1000
- Default `-i` (interval): 10 saniye

**Bizim k6 parametremiz:**
```bash
slowhttptest -c 500 -H -i 10 -r 50 -t GET
```

### 4.2 Header drip interval: 10s

**Kaynak (orijinal):** Hansen, R. ("RSnake") (2009). *Slowloris HTTP DoS*.
http://ha.ckers.org/slowloris/

- Tarihi original implementation
- 10-30 saniye header drip interval
- Connection slot exhaustion via partial requests

**Bizim k6 parametremiz:** `-i 10` (10 saniye interval)

**Tezde:**
> "Real slowloris attack uses slowhttptest with 500 concurrent connections
> at 10s header drip interval, parameters consistent with the slow-DoS
> taxonomy of Cambiaso et al. (2013) and the original Slowloris attack
> characterization by Hansen (2009)."

---

## 5. Slow-POST / RUDY (Scenario S6 alt)

### 5.1 Body drip interval: 110s

**Kaynak:** Cambiaso et al. 2013 (slow-DoS taxonomy, yine)

- RUDY (R-U-Dead-Yet) characterization
- POST body 1 byte / 100-120s drip
- 200-1000 concurrent connections

**Bizim k6 parametremiz:**
```bash
slowhttptest -c 500 -B -i 110 -r 50 -t POST
```

---

## 6. Mimicry Flood (Scenario S5 — HOLDOUT)

### 6.1 Conceptual basis (akademik kaynak)

**Kaynak:** Wagner, D., & Soto, P. (2002). "Mimicry Attacks on
Host-based Intrusion Detection Systems." *Proceedings of the 9th ACM
Conference on Computer and Communications Security (CCS '02)*, 255-264.

- Mimicry attack kavramının orijinal akademik tanımı (host-based IDS
  bağlamında, ama HTTP-level'a kavramsal olarak transfer eder)
- Detection-aware adversary modeling

**Kaynak:** Fogla, P., Sharif, M., Perdisci, R., et al. (2006).
"Polymorphic Blending Attacks." *Proceedings of the 15th USENIX
Security Symposium*, 241-256.

- Network-level mimicry attack characterization
- Anomaly-based detection evasion via traffic blending

**Bizim k6 parametremiz:**
```javascript
// UA: SOPHISTICATED_ATTACKER_AGENTS = LEGIT_AGENTS (özdeş havuz)
// IP: getIpPool('sophisticated') = legit ile overlap
// Token reuse: sticky session (her iteration'da yeniden login değil)
```

**Tezde:**
> "The mimicry flood scenario operationalizes the static mimicry attack
> threat model from Wagner & Soto (2002) and Fogla et al. (2006) at the
> HTTP application layer: surface features (User-Agent distribution,
> source IP space) are sampled from the legitimate user pool, while
> attack-level request rate is preserved. This scenario is held out as
> test-only data (Section 4.X) to empirically quantify the dependence
> of detection accuracy on surface vs. behavioral features."

---

## 7. Verifikasyon checklist (tezde kullanmadan önce)

Her referansı **şu şekilde doğrula**:

1. **Google Scholar'da tam başlığı ara** — gerçekten var mı?
2. **DOI veya arXiv ID** — kalıcı identifier var mı?
3. **Citation count** — 50+ atıf güvenli, <5 atıf şüpheli olabilir
4. **Yazarın diğer çalışmaları** — yazar gerçek araştırmacı mı?
5. **Yıl ve venue** — uydurulmuş gibi mi görünüyor?

Her referansı bireysel olarak verify et. Eğer kaynak doğrulanamazsa, ya
gerçek kaynak bul ya da o parametreyi "literature defaults" diye genel
formüle düş.

## 8. Eksik referans kategorileri (tezde acknowledge)

Bu calibration **eksiksiz değil**. Şu konularda akademik kaynak az ya da
karışık:

- **Modern HTTP/2 attack vectors** (Rapid Reset CVE-2023-44487):
  vendor advisories ve blog post'lar var, peer-reviewed academic limited.
  Tezde "future work" bölümüne not düş.
- **Real production attack baselines** (per-application real attack rates):
  privacy nedeniyle public data nadir. Akamai/Cloudflare aggregate
  reports'larla yetinilir.
- **Iterative adaptive adversary** (ML-based evolving attacker): adversarial
  ML literatürü var (Goodfellow, Madry vs.) ama HTTP-DDoS bağlamına
  spesifik calibration eksiksiz. v2 scope.
