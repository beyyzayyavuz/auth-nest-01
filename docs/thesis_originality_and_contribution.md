# Tez Özgünlüğü ve Katkı — Dürüst Değerlendirme

Bitirme tezi için yapıyor olsan da reviewer "neden bu çalışma?" sorusunu
soracak. Bu doküman, neyin **özgün olmadığını**, neyin **katkı olarak
çerçevelenebileceğini** ve **hangi anlatım stratejisinin** seni en güçlü
tarafıyla göstereceğini ayırıyor.

---

## 1. Özgün OLMAYAN şeyler (kabul et, savunma yapma)

Bu liste tezin özünü oluşturuyor ama **yeni** değil. Reviewer karşısında
bunları "yeni bir şey buldum" gibi sunarsan kredibilite kaybedersin.

| Bileşen | Literatürdeki yaygınlığı |
|---|---|
| Application-layer DDoS detection | 2000'lerden beri yüzlerce makale |
| Behavioral HTTP traffic analysis | Klasik, çok sayıda çalışma |
| Inter-arrival time entropy analysis | Klasik network security tekniği |
| Endpoint popularity entropy / Zipf | Kapsamlı literatür |
| Random Forest / Isolation Forest detection | Yaygın baseline |
| CIC-DDoS2019 üzerinde validation | Pek çok makale benzer şey yapıyor |
| NASA HTTP logs ile calibration | 1990'lardan beri kullanılıyor |
| Slowloris detection via connection-level features | Ericsson, Cloudflare blog'ları + akademik makaleler |
| nginx + NestJS engineering | Mühendislik, akademik katkı değil |
| k6 ile traffic generation | Toolchain, katkı değil |
| Mimicry attack farkındalığı | Adversarial ML literatüründe yaygın |

**Sonuç:** Tezdeki **hiçbir bileşen tek başına yeni değil.** Bu normal —
bitirme tezi de yeni algoritma icat etmez. Asıl iş **bu bileşenlerin nasıl
bir araya getirildiği**.

---

## 2. ÖZGÜNLÜK olarak çerçevelenebilecek şeyler

Senin durumunda gerçekten yeni veya az çalışılmış olan şeyler:

### 2.1 (Güçlü) Endpoint-cost-aware behavioral detection
**İddia:** "Behavior-based detection should weight features by per-endpoint
backend cost, because asymmetric resource consumption is the actual attack
mechanism."

Klasik DDoS detection'da tüm endpoint'lere eşit muamele edilir. "100 req/s
çok" denir. Ama:
- 100 req/s `/health` = sıfır yük
- 10 req/s `/search?q=expensive` = backend ölü

Senin yaklaşımın `endpointCostSum`, `endpointCostMean` gibi feature'ları
**explicit olarak** kullanıyor. Bu, çoğu existing detector'da yok veya
implicit. Empirik olarak gösterilebilir bir avantaj.

**Tezdeki konumlandırma:**
> "We argue that behavioral DDoS detection in modern applications must
> incorporate per-endpoint backend cost as a first-class feature, since
> low-volume but high-cost attacks (e.g., search bombing) bypass
> volumetric thresholds. We empirically calibrate cost weights from
> production-like traffic and integrate them into the feature set."

Bu **defendable bir contribution**. Reviewer'a "endpoint-cost-aware"
specifically ne demek diye sorulduğunda concrete answer'ın var.

### 2.2 (Orta) Behavior-vs-Surface ayrımı (Mimicry holdout)
**İddia:** "Most behavior-based detectors actually rely on surface features
(UA, IP) for their accuracy. We separate these signals via held-out mimicry
attack scenario."

Senin Day 17'deki mimicry-attack-holdout deney tasarımı:
- Train: naive flood (UA/IP attacker'ı belli ediyor)
- Test: mimicry flood (UA/IP legitimate ile aynı havuzda)

Bu, "modelin gerçekten **davranış** mı yoksa **yüzeysel sinyal** mi
öğrendiğini" empirik olarak ölçer.

Çoğu mevcut makale:
- (a) Sadece naive saldırı kullanır → surface'a overfit eder, fark etmez
- (b) Mimicry'i mention eder ama test etmez

Senin deney bu boşluğu doldurur. Sonuç ne çıkarsa çıksın (recall düşse bile)
yayınlanabilir bilgi: **"Modern behavioral detection ne kadar UA/IP'ye
bağımlı?"** sorusunun ampirik cevabı.

**Tezdeki konumlandırma:**
> "We propose mimicry-attack-holdout as an explicit experimental protocol
> for distinguishing behavior-based from surface-based detection. The
> in-distribution vs. out-of-distribution recall differential quantifies
> the robustness of detection under adversarial conditions."

### 2.3 (Orta) Cross-trace structural-prior calibration
**İddia:** "Calibration datasets older than the deployment context can be
used responsibly when distinguishing structural priors from absolute
parameters. We provide an explicit methodology."

NASA/Calgary'i bilinçli şekilde "structural prior" olarak kullanmak,
**absolute parameter** olarak değil; ve her iki dataset'i cross-validate
etmek. Doküman 1.3'teki formülasyon.

Çoğu bitirme tezi:
- (a) Tek dataset kullanır, tek parametre kümesi alır, transfer eder, savunamaz
- (b) Hiç calibration yapmaz, ad-hoc parametrelerle simülasyon kurar

Senin yaklaşımın **methodological transparency** sunar. Yeni bir teknik
değil ama disipline edilmiş yöntem.

### 2.4 (Zayıf-orta) Unified multi-class framework
**İddia:** "Single feature set and classifier pipeline handles three distinct
application-layer attack classes (high-rate flood, low-rate bot, slowloris)
without per-class specialization."

Mevcut literatürde:
- Slowloris detection makaleleri var (connection-level features)
- HTTP flood detection makaleleri var (rate + entropy)
- Low-rate scraping detection makaleleri var (timing patterns)

**Aynı feature seti** ile her üçünü 4-class classifier'da yapan çalışma
nispeten az. Senin Tier 0/1/2 schema bunu sağlıyor.

Ama dikkat: bu zayıf bir contribution çünkü "yeni bir teknik" değil,
"mevcut tekniklerin entegrasyonu". Tezde mention et ama merkez yapma.

### 2.5 (Engineering, akademik değil) Reproducible instrumentation pipeline
nginx + NestJS interceptor + Prisma `$on('query')` + AsyncLocalStorage
backend cost capture pipeline'ı. **Akademik katkı değil ama reusable
engineering artifact.**

Tezde "Implementation" bölümünde detayla, ama "Contribution" listesinde
3. veya 4. sırada olsun.

### 2.6 (Methodological) Random-label permutation + panic-mode disclosure
- Random-label permutation testi — data leakage savunması
- Panic-mode pivot — negative result için kabul edilen tasarım

İkisi de methodological transparency. Az tezde olur. Önemli ama zayıf
contribution.

---

## 3. Önerdiğim ana araştırma sorusu (research question)

Tezin merkezi soru olarak **şunu** kullanmanı tavsiye ederim:

> **"When attackers mimic legitimate user surface features (User-Agent
> distribution, source IP heterogeneity), can behavior-based detection
> still discriminate them from real users — and which behavioral features
> contribute most to the residual discrimination?"**

Bu soru:
- **Dar ve odaklı** (savunulur)
- **Empirik olarak test edilebilir** (mimicry holdout var)
- **Sonucu negatif çıksa bile değerli** (panic-mode resilient)
- **Özgün-ish** (literatürde mention edilir ama az test edilir)
- **Modern context'te relevant** (modern attack'lar UA/IP rotation yapar)

### Yan sorular (bunlar contribution'ı destekler):
1. Endpoint-cost-aware feature'lar cost-asymmetric saldırılarda recall'u ne
   kadar iyileştirir? (ablation gösterir)
2. Connection-level features (header_recv_duration vs.) slow-loris vs
   low-rate-bot ayrımında ne kadar baskın? (real_slowloris scenario gösterir)
3. Cross-trace calibration (NASA + Calgary) parametreleri ne kadar tutarlı?
   Bu, structural prior çerçevesini ne kadar destekler?

---

## 4. Tez başlık önerileri

Mevcut "Application-Layer DDoS Detection" kafadan sıkıcı ve genel. Şunlar
daha odaklı:

1. **"Mimicry-Robust Behavioral Detection of Application-Layer Denial of
   Service Attacks: An Empirical Study"** — odak mimicry, dürüst
   "empirical study" framing'i.

2. **"Endpoint-Cost-Aware Behavioral Discrimination of Low-Volume HTTP
   DDoS Attacks"** — odak endpoint cost, low-volume.

3. **"Behavior-Based vs. Surface-Based Discrimination in Application-Layer
   DDoS Detection: A Mimicry Attack Holdout Analysis"** — en doğrudan,
   methodologically güçlü.

4. **"Cross-Trace Calibrated Behavioral Detection of HTTP Flood and
   Slow-Rate Application-Layer Attacks"** — calibration framework'ü
   öne çıkarır.

**Tavsiyem:** 1 veya 3. Bunlar tezin asıl katkısı (mimicry holdout +
empirical analysis) ile uyumlu.

---

## 5. Ana contribution claim'leri (tezin başında ve sonunda)

Tezin "Contributions" bölümünde **net 4 madde** olmalı:

> **Bu tezin katkıları:**
>
> 1. **(Empirical)** Modern bir web uygulaması (NestJS/nginx/PostgreSQL)
>    üzerinde, üç farklı application-layer saldırı sınıfını (HTTP flood,
>    low-rate bot, real slowloris) **birleşik bir feature framework
>    içinde** detect eden bir behavioral detection pipeline'ının ampirik
>    değerlendirmesi.
>
> 2. **(Methodological)** Mimicry-attack-holdout adı verilen, davranışsal
>    detector'ların **yüzeysel sinyallere (UA, IP) bağımlılığını ölçen**
>    bir deneysel protokol. In-distribution vs. out-of-distribution recall
>    farkını niceliksel olarak raporlar.
>
> 3. **(Engineering)** Per-endpoint backend cost'un dynamic instrumentation
>    yoluyla yakalanması ve behavioral feature setine entegre edilmesi
>    (Prisma `$on('query')` + AsyncLocalStorage tabanlı pipeline).
>    Asymmetric resource exhaustion attack'larında recall iyileştirme
>    miktarı ablation study ile raporlanır.
>
> 4. **(Methodological)** Klasik web traffic dataset'lerinin (NASA-1995,
>    Calgary-1994/95) "yapısal prior" olarak kullanılması ve modern context'e
>    transferi için açık bir cross-trace calibration metodolojisi.

Bu dört madde:
- Her biri **specific**, "behavioral DDoS detection" gibi bulanık değil
- Her biri **empirik olarak gösterilebilir** (sayısal sonuç var)
- Hiçbiri **abartılmamış** ("novel algorithm" demiyor)
- Hepsi **tezdeki mevcut planla uyumlu** — yeni iş eklemiyor

---

## 6. NE DEME

Tez savunmasında **şu cümleleri kurma**:

- "Bu yeni bir DDoS tespit algoritmasıdır." → Hayır, RF/IF kullanıyorsun.
- "Mevcut yöntemlerden daha iyi sonuç verir." → Head-to-head SOTA
  benchmark yapmıyorsun.
- "Bu yöntem production'da kullanılabilir." → Synthetic-only validation,
  scope dar.
- "Adaptive adversary'e karşı dayanıklı." → Sadece statik mimicry test
  ettin, iteratif değil.
- "Detection latency milisaniyeler düzeyinde." → Offline post-hoc
  hesapladın, online streaming değil.

Bunları **sadece reviewer sorarsa** dürüstçe sınırla:
- "Detection latency was computed post-hoc; online streaming detection
  is left as future work."
- "Adaptive adversary evaluation is limited to static mimicry; iterative
  ML-based attackers are scope of future work."

---

## 7. NE DE

Tez savunmasında **şu cümleler güvenli ve doğru**:

- "We empirically evaluate behavioral discrimination of three application-
  layer attack classes within a unified feature framework on a modern
  web application stack."
- "We introduce a mimicry-attack-holdout experimental protocol that
  quantifies the contribution of surface features vs. behavioral features
  to detection accuracy."
- "We integrate dynamically-captured per-endpoint backend cost into the
  feature set and demonstrate its contribution via ablation."
- "We use classical web traffic traces as structural priors with explicit
  separation of distribution shape from absolute parameters, validated
  via cross-trace consistency analysis."

---

## 8. Dürüst kapanış

Bu tez **akademik olarak orijinal mi?** Sınırlı şekilde. Her bileşen
literatürde var. **Methodologically iyi yapılmış mı olacak?** Eğer planı
takip edersen evet — çok az bitirme tezi mimicry holdout, cross-trace
calibration, ablation study, random-label permutation savunması, panic-mode
resilient design hepsini bir arada yapar.

**Asıl katkı:** Her bileşen ayrı ayrı yeni değil, ama **disiplinli birleşim
+ explicit deney tasarımı + dürüst limitations** bitirme tezi seviyesinde
defensible bir çalışma yaratır.

Bunun ötesinde "Bu Yeni Bir Şey" iddiası yapma. Yapsan da reviewer'lar bu
literatürü biliyor, kıracak. Tutamayacağın iddia tutmaktan, sınırlı ama
sağlam katkı iddiası daha güçlüdür.

**Bir cümlede:** Senin özgün tarafın **"behavioral vs. surface
discrimination"** sorusunu mimicry holdout deneyi ile empirik test eden,
modern bir uygulama bağlamında çalışan ve calibration için klasik
trace'lerin doğru kullanımını gösteren bir empirical study yapmak. Bu
**bitirme tezi için yeterli**, **publication için yetersiz**, **reviewer'a
karşı savunulur**.
