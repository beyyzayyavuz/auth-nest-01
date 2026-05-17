# Bug Fix Plan — Step-by-Step

**Süre tahmini:** ~1 gün (6-8 saat compute + 1-2 saat aktif iş)
**Geri dönüş güvencesi:** Eski sonuçlar her aşamada korunuyor; gerekirse 5 dakikada eski versiyona geri dönebilirsin.

---

## 🎯 Hedef

İki bug'ı düzelt, pipeline'ı yeniden koş, eski vs yeni sonuçları karşılaştır, en iyisini al.

| # | Bug | Dosya | Etki | Düzeltme süresi |
|---|---|---|---|---|
| 1 | UserService ayrı Prisma client kullanıyor | `src/user/user.service.ts` | Search endpoint dbTime ölçülmüyor | 5 dk |
| 2 | k6 legit flow think time sleep'lemiyor | `k6/common/legitimate-user-flow.js` | Normal_user RPS gerçekçi değil | 5 dk |

---

## 🗂️ Aşama 0 — Hazırlık ve Yedek (15 dk)

### 0.1 — Mevcut sonuçları yedekle

Postgres database'ini ve mevcut feature/result dosyalarını **şu anki halini sakla**. Eğer yeni sonuçlar kötü çıkarsa geri dönmek için.

```bash
cd /Users/beyzayavuz/Desktop/auth-nest-01

# Mevcut sonuçları zip'le (analiz çıktıları)
mkdir -p backups
zip -r backups/results_OLD_$(date +%Y%m%d).zip \
    analysis/data/results/ \
    analysis/data/features/ \
    analysis/data/parsed/ \
    analysis/data/baselines/

# Postgres dump (eski trafik verisi)
docker exec ddos_postgres pg_dump -U research -d ddos_research \
    > backups/db_OLD_$(date +%Y%m%d).sql

ls -lh backups/
```

Bu iki dosya yedeğin. Yeni sonuçlar kötü çıkarsa **bu yedeklere geri dönebilirsin** (aşağıda "Rollback" bölümü).

### 0.2 — Yeni git branch aç

```bash
cd /Users/beyzayavuz/Desktop/auth-nest-01
git status  # önce temiz olduğunu doğrula

# Eğer commit'lenmemiş değişiklik varsa onları önce commit et:
git add -A && git commit -m "checkpoint: before bug fixes"

# Şimdi yeni branch:
git checkout -b bugfix-think-and-prisma
git branch  # iki branch görmelisin: main (veya master) + bugfix-...
```

Bundan sonra **tüm değişiklikler bu yeni branch'te**. Main bozulmayacak.

### 0.3 — Hangi branch'tesin emin ol

```bash
git branch --show-current
# Çıktı: bugfix-think-and-prisma  ← bu olmalı
```

---

## 🔧 Aşama 1 — Bug Fix #1: UserService Prisma Client (5 dk)

### 1.1 — Mevcut hatalı kod

`src/user/user.service.ts` satır 11:

```typescript
@Injectable()
export class UserService {
  private prisma = new PrismaClient();   // ← BUG: ayrı instance
  ...
}
```

Bu ayrı bir Prisma client instance üretiyor, yani PrismaService'in `$extends({ query: ... })` interceptor'unu **bypass ediyor**. Sonuç: search query timing'leri RequestLog'a yansımıyor.

### 1.2 — Düzeltilmiş kod

Dosyayı şu hale getir (sadece import ve constructor değişiyor):

```typescript
import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';   // ← YENİ

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}              // ← DEĞİŞTİ

  async createUser(email: string, password: string): Promise<User> {
    const hashedPassword = await bcrypt.hash(password, 10);
    return this.prisma.user.create({
      data: { email, password: hashedPassword },
    });
  }
  // ... geri kalan tüm methodlar aynı, sadece `this.prisma.user.X` çağrıları
  // artık PrismaService'in extension'ı üzerinden gidecek
}
```

**Önemli not**: Geri kalan tüm method'lar aynı kalıyor (findUserByEmail, findUserById, updateUser, changePassword, deleteUser, simulateSearch). Sadece **import** ve **constructor** satırlarını değiştir.

### 1.3 — UserModule'da PrismaModule import'u kontrol et

`src/user/user.module.ts` aç. Eğer şöyleyse:

```typescript
@Module({
  providers: [UserService],
  controllers: [UserController],
  exports: [UserService],
})
```

Şöyle değiştir:

```typescript
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],   // ← EKLE
  providers: [UserService],
  controllers: [UserController],
  exports: [UserService],
})
```

### 1.4 — Test et (uygulamayı başlat)

```bash
# Terminal 1 — postgres + nginx
docker compose up -d postgres nginx

# Terminal 2 — NestJS
npm run start:dev

# Bekle: "Application is running on: http://localhost:3000"
```

Eğer hata alırsan, çoğu zaman `PrismaModule` import'unu unuttuğun içindir. Geri dönüp 1.3'ü kontrol et.

### 1.5 — Manuel test: search endpoint dbTime ölçüyor mu?

```bash
# Terminal 3 — bir login + search isteği gönder
TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user01@example.com","password":"TestUser@2026!"}' \
  | jq -r '.accessToken')

curl -s "http://localhost:8080/user/search?q=test" \
  -H "Authorization: Bearer $TOKEN" > /dev/null

# RequestLog'da son search isteğine bak
docker exec ddos_postgres psql -U research -d ddos_research -c \
  "SELECT \"routeTemplate\", \"dbQueryCount\", \"dbTotalTimeMs\", \"cpuTimeMs\" 
   FROM \"RequestLog\" 
   WHERE \"routeTemplate\" LIKE '%search%' 
   ORDER BY timestamp DESC LIMIT 1;"
```

**Beklenen**: `dbQueryCount` > 0 ve `dbTotalTimeMs` > 0.

**Eski hâlinde**: ikisi de 0 oluyordu.

Eğer hâlâ 0 ise: PrismaModule import'unu unuttun, ya da uygulama restart edilmedi. Geri dön.

### 1.6 — Commit

```bash
cd /Users/beyzayavuz/Desktop/auth-nest-01
git add src/user/user.service.ts src/user/user.module.ts
git commit -m "fix: UserService now uses PrismaService for query timing capture"
```

---

## 🔧 Aşama 2 — Bug Fix #2: THINK Sleep (5 dk)

### 2.1 — Mevcut hatalı kod

`k6/common/legitimate-user-flow.js` içinde 6 yer:

| Satır no civarı | Kod |
|---|---|
| ~121 | `THINK.medium();` |
| ~165 | `THINK.short();` |
| ~173 | `THINK.medium();` |
| ~177 | `THINK.long();` |
| ~178 | `THINK.medium();` |
| ~183 | `THINK.medium();` |
| ~192 | `THINK.long();` |

(Tam satır numaraları biraz değişebilir, ama `THINK.` ile aratınca hepsini bulursun.)

### 2.2 — Düzeltme

Her birini `sleep(THINK.x())` ile sar. Örnekler:

```javascript
// ÖNCE:
THINK.medium();

// SONRA:
sleep(THINK.medium());
```

`sleep` zaten dosyanın başında import edilmiş — kontrol et:

```javascript
import { check, sleep, group } from 'k6';   // ← sleep burada olmalı
```

Varsa eksik değil, hazırsın.

### 2.3 — Find/replace komutu (Mac sed)

```bash
cd /Users/beyzayavuz/Desktop/auth-nest-01

# Önce yedek al (sed in-place için)
cp k6/common/legitimate-user-flow.js k6/common/legitimate-user-flow.js.bak

# Üç THINK çağrısını sleep ile sar:
sed -i '' 's/THINK\.short();/sleep(THINK.short());/g' k6/common/legitimate-user-flow.js
sed -i '' 's/THINK\.medium();/sleep(THINK.medium());/g' k6/common/legitimate-user-flow.js
sed -i '' 's/THINK\.long();/sleep(THINK.long());/g' k6/common/legitimate-user-flow.js

# Kontrol et
grep -n "THINK\." k6/common/legitimate-user-flow.js
```

**Beklenen çıktı**: tüm `THINK.x()` çağrıları `sleep(THINK.x())` formunda olmalı.

Eğer her şey doğruysa backup'ı sil:

```bash
rm k6/common/legitimate-user-flow.js.bak
```

### 2.4 — Commit

```bash
git add k6/common/legitimate-user-flow.js
git commit -m "fix: apply log-normal think times via sleep() in legitimate flow"
```

---

## ✅ Aşama 3 — Düzeltmeleri Doğrula (15 dk)

### 3.1 — Mini smoke test

Çok kısa bir senaryo koştur. Tek dakikalık legit traffic + spot kontrol.

```bash
# Postgres + nginx ayağa kalkık olmalı (Aşama 1.4'ten)
# NestJS de çalışıyor olmalı

# Önce S1'in eski verilerini temizle (sadece test)
docker exec ddos_postgres psql -U research -d ddos_research -c \
  "DELETE FROM \"RequestLog\" WHERE \"scenarioId\" = 'S1_smoke_test';"

# 60 saniyelik smoke
SCENARIO_ID=S1_smoke_test BASE_URL=http://localhost:8080 \
  k6 run --vus 5 --duration 60s k6/scenarios/01_legitimate_only.js

# Kontrol et: gerçekçi rate mi?
docker exec ddos_postgres psql -U research -d ddos_research -c \
  "SELECT 
     COUNT(*) AS total_requests,
     COUNT(DISTINCT ip) AS unique_ips,
     COUNT(*) * 1.0 / COUNT(DISTINCT ip) / 60 AS req_per_ip_per_sec
   FROM \"RequestLog\" WHERE \"scenarioId\" = 'S1_smoke_test';"
```

**Beklenen sonuç (BUG FIXED)**:
- `req_per_ip_per_sec` ≈ **0.1 – 0.5** (gerçekçi user davranışı)

**Eski (BUG VARDI)**:
- `req_per_ip_per_sec` ≈ **5 – 20** (think time uygulanmadığı için)

Eğer rate hâlâ yüksekse, sleep wrap'i çalışmamış. Geri dön.

### 3.2 — Search endpoint dbTime kontrolü

```bash
docker exec ddos_postgres psql -U research -d ddos_research -c \
  "SELECT 
     \"routeTemplate\",
     ROUND(AVG(\"dbTotalTimeMs\")::numeric, 2) AS avg_db_ms,
     ROUND(AVG(\"cpuTimeMs\")::numeric, 2) AS avg_cpu_ms,
     COUNT(*) AS n
   FROM \"RequestLog\" 
   WHERE \"scenarioId\" = 'S1_smoke_test'
   GROUP BY \"routeTemplate\";"
```

**Beklenen**: `/user/search` satırı için `avg_db_ms` > 0.

Eğer hâlâ 0 ise → UserService fix'i çalışmamış. Geri dön Aşama 1.

### 3.3 — Smoke verisini temizle

```bash
docker exec ddos_postgres psql -U research -d ddos_research -c \
  "DELETE FROM \"RequestLog\" WHERE \"scenarioId\" = 'S1_smoke_test';"
```

---

## 🧹 Aşama 4 — Database'i tamamen temizle (5 dk)

Şimdi gerçek senaryo koşumu için temiz başlangıç.

```bash
docker exec ddos_postgres psql -U research -d ddos_research <<'EOF'
TRUNCATE "RequestLog" CASCADE;
TRUNCATE "Connection" CASCADE;
TRUNCATE "BehavioralSession" CASCADE;
TRUNCATE "WindowLabel" CASCADE;
TRUNCATE "Scenario" CASCADE;
TRUNCATE "EndpointCostProfile" CASCADE;
-- LoginAttempt ve IpBlock kalsın (user setup'ı bozulmasın)
SELECT 'CLEANED' AS status;
EOF
```

**Önemli**: `User` ve `LoginAttempt` tablolarını TRUNCATE etmedik. Test kullanıcıların duruyor. Eğer onları da temizlersen önce kullanıcıları yeniden kaydetmen gerekir.

---

## 🏃 Aşama 5 — Senaryoları Yeniden Koş (~3-4 saat)

### 5.1 — Mac uyumasın

```bash
# Yeni terminal aç, oraya yapıştır (sonra arka planda kalsın)
caffeinate -dimsu &
echo "caffeinate started, PID: $!"
```

### 5.2 — Her senaryo için Scenario kaydı + k6 koş

Aşağıdaki blok her senaryo için ayrı ayrı çalıştırılabilir. **Aralarında 1-2 dakika bekle** (recovery period için).

```bash
# Helper fonksiyon (bash session başına bir kere)
run_scenario() {
  local SID=$1
  local FILE=$2
  echo "=== Starting $SID at $(date +%H:%M:%S) ==="
  
  # Scenario kaydı
  docker exec ddos_postgres psql -U research -d ddos_research -c \
    "INSERT INTO \"Scenario\" (id, name, \"startedAt\") 
     VALUES ('$SID', '$SID', NOW())
     ON CONFLICT (id) DO UPDATE SET \"startedAt\" = NOW(), \"endedAt\" = NULL;"
  
  # k6 koş
  SCENARIO_ID=$SID BASE_URL=http://localhost:8080 \
    k6 run "k6/scenarios/$FILE"
  
  # Scenario kapat
  docker exec ddos_postgres psql -U research -d ddos_research -c \
    "UPDATE \"Scenario\" SET \"endedAt\" = NOW() WHERE id = '$SID';"
  
  echo "=== Finished $SID at $(date +%H:%M:%S) ==="
  sleep 60  # recovery
}

# Tüm senaryolar
run_scenario S1_legit_only          01_legitimate_only.js
run_scenario S2_http_flood          02_http_flood.js
run_scenario S3_low_rate_bot        03_low_rate_bot.js
run_scenario S4_credential_stuffing 04_credential_stuffing.js
run_scenario S5_mimicry_flood       05_mimicry_flood.js
```

**Süre**: Her senaryo ~30 dk (mimicry, flood, credential 30 dk; low-rate bot zaten 30 dk fixed). S1 düşünme süresiyle artık ~30 dk gerçekten alır.

**Toplam**: ~3 saat.

### 5.3 — Slowloris (S6) ayrı koş

```bash
# slowhttptest container'ı başlat
docker compose --profile attack up -d slowhttptest

# Scenario kaydı
docker exec ddos_postgres psql -U research -d ddos_research -c \
  "INSERT INTO \"Scenario\" (id, name, \"startedAt\") 
   VALUES ('S6_slowloris', 'S6_slowloris', NOW())
   ON CONFLICT (id) DO UPDATE SET \"startedAt\" = NOW(), \"endedAt\" = NULL;"

# slowloris koş (30 dk)
docker exec ddos_slowhttptest slowhttptest \
  -c 200 -H -i 10 -r 200 -t GET \
  -u http://host.docker.internal:8080/ \
  -p 3 -l 1800 -x 24 -k 1000

# Scenario kapat
docker exec ddos_postgres psql -U research -d ddos_research -c \
  "UPDATE \"Scenario\" SET \"endedAt\" = NOW() WHERE id = 'S6_slowloris';"
```

### 5.4 — Sanity check

```bash
docker exec ddos_postgres psql -U research -d ddos_research -c \
  "SELECT \"scenarioId\", COUNT(*) FROM \"RequestLog\" 
   WHERE \"scenarioId\" IS NOT NULL GROUP BY \"scenarioId\" ORDER BY 1;"
```

**Beklenen**: Her S1-S5 için on binlerce, S6 için birkaç bin (sparse).

---

## 🔬 Aşama 6 — Feature Pipeline + Model (~2 saat)

```bash
cd /Users/beyzayavuz/Desktop/auth-nest-01
source analysis/venv/bin/activate   # eğer venv kullanıyorsan

# Tier 1: Connections (nginx 408 enrichment dahil)
python analysis/scripts/10_tier1_connections.py

# Endpoint Cost Profile (S1 trafiğinden)
python analysis/scripts/11_endpoint_cost.py

# Tier 2: Window features
python analysis/scripts/12_tier2_features.py

# Tier 3: Global
python analysis/scripts/13_tier3_global.py

# Tier 4: Sessions
python analysis/scripts/14_tier4_sessions.py

# Baseline distance (Markov + KS)
python analysis/scripts/15_baseline_distance.py

# Merge
python analysis/scripts/16_merge_all_features.py

# Dataset split
python analysis/scripts/17_prepare_dataset.py

# Feature selection + train_ready
python analysis/scripts/18_feature_selection.py

# Baselines
python analysis/scripts/19_baseline_rate_threshold.py
python analysis/scripts/20_baseline_ewma_cusum.py
python analysis/scripts/21_baseline_random_forest.py

# Proposed model
python analysis/scripts/25_proposed_model.py
python analysis/scripts/26_mimicry_holdout_analysis.py

# Latency + FPR
python analysis/scripts/22_detection_latency.py
python analysis/scripts/23_detection_latency_by_scenario.py
python analysis/scripts/24_fpr_per_legit_ip_minute.py

# Ablation
python analysis/scripts/27_ablation_study.py

# Tables
python analysis/scripts/30_metrics_tables.py

# Figures
python analysis/scripts/31_figures.py
python analysis/scripts/32_calibration_validity.py
python analysis/scripts/33_mimicry_analysis.py
```

**Süre**: ~1-2 saat (Tier 3 yavaş olabilir).

Hata alırsan: o script'in son hatasına bak, çoğu zaman feature column eksikliği veya NaN problemi. Düzelt, devam et.

---

## 📊 Aşama 7 — Eski vs Yeni Karşılaştırma (30 dk)

### 7.1 — Yeni sonuçları kaydet

```bash
mkdir -p backups/results_NEW_$(date +%Y%m%d)
cp -r analysis/data/results/* backups/results_NEW_$(date +%Y%m%d)/
```

### 7.2 — Karşılaştırma tablosu

Bu Python script'i yeni/eski sonuçları yan yana koyacak:

```bash
cat > /tmp/compare_results.py <<'EOF'
import pandas as pd
from pathlib import Path

OLD = Path("backups/results_OLD_20260517")  # senin OLD klasörünün adı
NEW = Path("analysis/data/results")

print("=" * 70)
print("COMPARISON: OLD (bugs) vs NEW (fixed)")
print("=" * 70)

# Table 1: Overall
print("\n--- Overall metrics ---")
old1 = pd.read_csv(OLD / "table1_overall.csv", index_col=0)
new1 = pd.read_csv(NEW / "table1_overall.csv", index_col=0)
cmp = pd.concat([old1.add_suffix("_OLD"), new1.add_suffix("_NEW")], axis=1)
print(cmp.round(4))

# Mimicry
print("\n--- Mimicry holdout ---")
old_m = pd.read_csv(OLD / "mimicry_baseline_vs_proposed.csv")
new_m = pd.read_csv(NEW / "mimicry_baseline_vs_proposed.csv")
print("OLD:"); print(old_m)
print("\nNEW:"); print(new_m)

# Ablation
print("\n--- Ablation key rows ---")
key_groups = ["all", "ua_only", "rate_only", "endpoint_only"]
old_a = pd.read_csv(OLD / "ablation_study_results.csv")
new_a = pd.read_csv(NEW / "ablation_study_results.csv")
for g in key_groups:
    o = old_a[old_a["group"] == g][["val_accuracy", "mimicry_recall_as_flood", "mimicry_evasion_rate"]].iloc[0]
    n = new_a[new_a["group"] == g][["val_accuracy", "mimicry_recall_as_flood", "mimicry_evasion_rate"]].iloc[0]
    print(f"\n  {g}:")
    print(f"    val_acc:        OLD={o['val_accuracy']:.4f}  NEW={n['val_accuracy']:.4f}")
    print(f"    mimicry recall: OLD={o['mimicry_recall_as_flood']:.4f}  NEW={n['mimicry_recall_as_flood']:.4f}")
    print(f"    evasion rate:   OLD={o['mimicry_evasion_rate']:.4f}  NEW={n['mimicry_evasion_rate']:.4f}")

# Feature importance top 5
print("\n--- Top 5 features ---")
old_f = pd.read_csv(OLD / "proposed_model_feature_importance.csv").head(5)
new_f = pd.read_csv(NEW / "proposed_model_feature_importance.csv").head(5)
print("OLD:"); print(old_f)
print("\nNEW:"); print(new_f)
EOF

python /tmp/compare_results.py
```

### 7.3 — Karar tablosu

Karşılaştırmaya bakarak şu kararları ver:

| Senaryo | Karar |
|---|---|
| Mimicry recall **artmış** (örn. %92 → %95) ve ablation rate-only **makul** (~%75-85) | ✅ Yeni versiyon kullan |
| Mimicry recall **aynı** (~%92) ve ablation rate-only **makul** | ✅ Yeni versiyon kullan (methodology daha temiz) |
| Mimicry recall **düşmüş** (%92 → %70-80) ve ablation rate-only **şişmiş** (%95+) | ⚠️ Karar an: ya yeni versiyonu "harder test setting" diye sun, ya eskiye dön |
| Mimicry recall **çok düşmüş** (%92 → %60↓) | ❌ Eski versiyona dön (rollback aşağıda) |

---

## 🔀 Aşama 8a — Yeni versiyon iyiyse: Merge

```bash
# Thesis text'i güncelle (yeni sayılarla)
# - abstract, results, discussion, conclusion, full — tüm sayıları yeniden yaz
# Sonra:

git add -A
git commit -m "results: regenerated after bugfixes, updated thesis numbers"

# Main'e merge
git checkout main
git merge bugfix-think-and-prisma
git push origin main   # opsiyonel
```

## ⏪ Aşama 8b — Yeni versiyon kötüyse: Rollback

```bash
# Branch'i sil (commit'ler kaybolur ama backup zip'in duruyor)
git checkout main
git branch -D bugfix-think-and-prisma

# Eski verileri restore et:
# 1. Postgres'i restore et
docker exec -i ddos_postgres psql -U research -d ddos_research \
  < backups/db_OLD_20260517.sql

# 2. Sonuç dosyalarını restore et
cd /Users/beyzayavuz/Desktop/auth-nest-01
unzip -o backups/results_OLD_20260517.zip

# 3. Limitations'a iki bug'ı dürüst yaz (şu anki Discussion §5.6'da zaten var)
# Mevcut sonuçlarla devam.
```

---

## 📝 Aşama 9 — Thesis text güncelleme (yeni versiyon kullanılıyorsa)

Yeni sayıları şu dosyalara yaz:
- `docs/thesis_abstract.md`
- `docs/thesis_results.md` (Table 1, 2, 3, 4, 5, 6 hepsi)
- `docs/thesis_discussion.md`
- `docs/thesis_conclusion.md`
- `docs/thesis_full.md`

Find-replace komutu (find/replace değerlerini yeni sonuçlardan al):

```bash
# Örnek (yeni sayılar X, Y, Z bilinince):
OLD_RECALL="91.96"
NEW_RECALL="XX.XX"   # yeni mimicry recall

for f in docs/thesis_*.md; do
  sed -i '' "s/${OLD_RECALL}/${NEW_RECALL}/g" "$f"
done
```

Sunum PPTX'ini de güncellemen gerek (`make_pptx_en.py` içindeki hardcoded sayılar).

---

## ⚠️ Yaygın Sorunlar ve Çözümleri

| Sorun | Çözüm |
|---|---|
| `NestJS başlamıyor: PrismaService not found` | `UserModule`'da `imports: [PrismaModule]` ekledin mi? |
| `k6: function 'default' not found` | Senaryo dosyasında `export default flow;` var mı? |
| `Postgres healthcheck fail` | `docker compose down && docker compose up -d postgres` |
| `k6 ramping-arrival-rate slow start` | Normal; preAllocatedVUs az olabilir, attivite yoğun olunca yetişir |
| `Tier 3 script çok yavaş` | Beklenen, O(N²). Mac uyumasın diye caffeinate açık olsun |
| `Feature script "scenario X has no rows"` | Senaryo koşumunda hata olmuş; o senaryoyu tekrar koş |
| `Disk dolu` | `docker system prune` ile temizle |

---

## 🎯 Zaman Çizelgesi (1 gün)

| Saat | Aşama | Aktivite |
|---|---|---|
| 09:00 - 09:30 | 0, 1, 2, 3 | Yedek + iki bug fix + smoke test |
| 09:30 - 09:35 | 4 | Database temizle |
| 09:35 - 12:35 | 5 | Senaryolar koşumu (3 saat, caffeinate açık) |
| 12:35 - 13:30 | öğle | (senaryolar arka planda devam ediyorsa öğle ye) |
| 13:30 - 15:30 | 6 | Feature pipeline + model + figures |
| 15:30 - 16:00 | 7 | Karşılaştırma + karar |
| 16:00 - 18:00 | 8 + 9 | Merge + thesis text update VEYA rollback |

---

## ✅ Başarı Kriterleri

Yeni versiyonu **kullan** kabul ederim eğer:
- ☑ Smoke test'te search endpoint dbTime > 0
- ☑ Smoke test'te req_per_ip_per_sec ≈ 0.1-0.5 (gerçekçi)
- ☑ Pipeline hatasız bitiyor
- ☑ Mimicry recall ≥ %85 (mevcut %92'den çok düşmemiş)
- ☑ Ablation rate-only ≤ %90 (model hâlâ rate'e bağımlı değil)
- ☑ UA-only ablation hâlâ düşük (~%10)
- ☑ Confusion matrix temiz

---

## 🆘 Acil Durum Komutları

**Her şeyi durdur:**
```bash
docker compose down
pkill -f "k6 run"
pkill caffeinate
```

**Tek branch geri dön:**
```bash
git checkout main
git stash  # commit'lenmemiş değişiklikleri sakla (gerekirse pop)
```

**Postgres'i sıfırla:**
```bash
docker compose down -v postgres   # volume da silinir
docker compose up -d postgres
# Kullanıcıları tekrar seed et (eğer User tablosunu kaybettiysen)
for i in 01 02 03 04 05 06 07 08 09 10; do
  curl -X POST http://localhost:8080/auth/register \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"user${i}@example.com\",\"password\":\"$(grep user0${i:0:1} k6/common/legitimate-user-flow.js | head -1 | grep -o "'[^']*'" | tr -d "'")\"}"
done
```

---

İyi şanslar! 🚀 Her aşamada takılırsan bana sor, çözeriz.
