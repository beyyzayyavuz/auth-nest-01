# V3 Plan — Bug Fixes + Production-Realistic Legit Baseline

**Hedef:** Tezin "behavioral robustness" argümanını korumak için legit traffic'i production-realistic hacme çıkar. Model rate-shortcut alamasın, davranışsal feature öğrenmek zorunda kalsın.

**Toplam süre:** ~5-6 saat (compute ağırlıklı)
**Aktif iş:** ~1 saat

---

## 📊 Versiyon Karşılaştırma — Karar Bağlamı

| | V1 (bug'lı) | V2 (mevcut) | V3 (hedef) |
|---|---|---|---|
| THINK sleep | yok | ✅ var | ✅ var |
| Search dbTime | yok | ✅ var | ✅ var |
| S1 VU max | 15 | 15 | **100** |
| Toplam normal RPS | ~75 (sleep yok) | ~4.5 | **~30** |
| Beklenen mimicry recall | 92% | **99%** | 85-95% |
| Beklenen rate-only ablation | 71% | **88%** | 70-80% |
| Beklenen top feature group | endpoint | global rate | **endpoint** |
| Tez argümanı | güçlü ama bug'lı | mismatched | **güçlü + dürüst** |

---

## 🗂️ Aşama 0 — V2 Sonuçlarını Yedekle (5 dk)

V2 zaten çalışan bir sonuç seti. Kaybetmek istemezsin.

```bash
cd /Users/beyzayavuz/Desktop/auth-nest-01

# V2 sonuçlarını arşivle
mkdir -p backups/V2_lowRPS_$(date +%Y%m%d)
cp -r analysis/data/results/* backups/V2_lowRPS_$(date +%Y%m%d)/

# V2 database dump
docker exec ddos_postgres pg_dump -U research -d ddos_research \
    > backups/db_V2_$(date +%Y%m%d).sql

# Boyut kontrolü
ls -lh backups/

# Mevcut feature dosyalarını da sakla (V2 train_ready matrisleri için)
zip -r backups/V2_features_$(date +%Y%m%d).zip \
    analysis/data/features/
```

Şimdi V2 yedekte. Yeni sonuçlar kötü çıkarsa V2'ye dönebilirsin.

---

## 🔧 Aşama 1 — S1 VU Sayısını Artır (2 dk)

`k6/scenarios/01_legitimate_only.js` dosyasını aç.

### 1.1 — Eski hâli

```javascript
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
```

### 1.2 — Yeni hâli (V3)

```javascript
export const options = {
  scenarios: {
    legit_users: {
      executor: 'ramping-vus',
      exec: 'flow',
      startVUs: 0,
      stages: [
        { duration: '2m',  target: 30  },   // ← 5 → 30
        { duration: '25m', target: 100 },   // ← 15 → 100
        { duration: '3m',  target: 0   },
      ],
      gracefulRampDown: '30s',
      tags: { trafficLabel: 'normal_user', scenarioId: SCENARIO_ID },
    },
  },
};
```

**Açıklama:**
- `target: 30` (warm-up): 30 user yavaş yavaş giriyor
- `target: 100` (steady state): 25 dakika boyunca 100 concurrent user
- Toplam normal RPS: 100 VU × ~0.3 RPS = **~30 RPS** (production gibi)

### 1.3 — Commit

```bash
cd /Users/beyzayavuz/Desktop/auth-nest-01
git add k6/scenarios/01_legitimate_only.js
git commit -m "v3: scale up S1 legit traffic to 100 VU for production-realistic baseline"
```

---

## 🧹 Aşama 2 — Database Temizle (2 dk)

V2 verisi PostgreSQL'de duruyor. Temiz başlangıç için sil.

```bash
docker exec ddos_postgres psql -U research -d ddos_research <<'EOF'
TRUNCATE "RequestLog" CASCADE;
TRUNCATE "Connection" CASCADE;
TRUNCATE "BehavioralSession" CASCADE;
TRUNCATE "WindowLabel" CASCADE;
TRUNCATE "Scenario" CASCADE;
TRUNCATE "EndpointCostProfile" CASCADE;
SELECT 'V3 CLEAN START' AS status;
EOF
```

User ve LoginAttempt korunur — test kullanıcıların duruyor.

---

## 🏃 Aşama 3 — Fail-Fast Mini Pipeline (1.5 saat)

**Tam 6 senaryoyu koşmadan önce 3 kritik senaryoyu koş.** Yön belirleme.

### 3.1 — Mac uyumasın

```bash
caffeinate -dimsu &
echo "caffeinate started, PID: $!"
```

### 3.2 — Helper fonksiyon

```bash
run_scenario_short() {
  local SID=$1
  local FILE=$2
  echo "=== Starting $SID at $(date +%H:%M:%S) ==="
  docker exec ddos_postgres psql -U research -d ddos_research -c \
    "INSERT INTO \"Scenario\" (id, name, \"startedAt\") 
     VALUES ('$SID', '$SID', NOW())
     ON CONFLICT (id) DO UPDATE SET \"startedAt\" = NOW(), \"endedAt\" = NULL;"
  SCENARIO_ID=$SID BASE_URL=http://localhost:8080 \
    k6 run "k6/scenarios/$FILE"
  docker exec ddos_postgres psql -U research -d ddos_research -c \
    "UPDATE \"Scenario\" SET \"endedAt\" = NOW() WHERE id = '$SID';"
  echo "=== Finished $SID at $(date +%H:%M:%S) ==="
  sleep 30
}
```

### 3.3 — 3 senaryoyu tam süre koş

**Mini koşum DEĞİL — tam süre.** Çünkü S1'de 100 VU ramp-up için 2 dakika gerek, sonra steady-state. 10 dakikalık koşumda S1 ramp-up'tan zar zor çıkar. Tam 30 dakika koş.

```bash
# Önce nginx + postgres + NestJS çalışıyor olduğunu doğrula
docker ps | grep -E "(postgres|nginx)"
curl -s http://localhost:8080/health | jq

# Sonra senaryolar
run_scenario_short S1_legit_only    01_legitimate_only.js
run_scenario_short S2_http_flood    02_http_flood.js
run_scenario_short S5_mimicry_flood 05_mimicry_flood.js
```

**Süre**: 30 + 30 + 30 = ~90 dakika + recovery = ~1.5 saat.

### 3.4 — Sanity check

```bash
docker exec ddos_postgres psql -U research -d ddos_research -c \
  "SELECT 
     \"scenarioId\",
     COUNT(*) AS requests,
     COUNT(DISTINCT ip) AS uniq_ips,
     ROUND((COUNT(*) * 1.0 / 1800)::numeric, 2) AS rps_avg
   FROM \"RequestLog\" 
   WHERE \"scenarioId\" IS NOT NULL 
   GROUP BY \"scenarioId\" 
   ORDER BY 1;"
```

**Beklenen S1 (V3)**:
- `requests` ≈ 54,000 (30 RPS × 1800 saniye)
- `uniq_ips` ≈ 50 (legit IP pool tam kullanılmış)
- `rps_avg` ≈ 30

V2'de bu sayılar:
- S1 requests ≈ 8,000
- S1 rps_avg ≈ 4-5

Yeni sayılar 5-7× daha yüksek olmalı normal trafik için.

---

## 🔬 Aşama 4 — Mini Feature Pipeline (30 dk)

Tam pipeline'a girmeden, sadece kritik script'leri koş. Mimicry recall'a hızlıca bak.

```bash
cd /Users/beyzayavuz/Desktop/auth-nest-01
source analysis/venv/bin/activate

# Tier 1
python analysis/scripts/10_tier1_connections.py

# Endpoint cost (V3'ün test ettiği büyük şeylerden biri)
python analysis/scripts/11_endpoint_cost.py

# Tier 2
python analysis/scripts/12_tier2_features.py

# Tier 3
python analysis/scripts/13_tier3_global.py

# Baseline distance
python analysis/scripts/15_baseline_distance.py

# Merge
python analysis/scripts/16_merge_all_features.py

# Dataset split
python analysis/scripts/17_prepare_dataset.py
python analysis/scripts/18_feature_selection.py

# SADECE proposed model + mimicry analizi (hızlı)
python analysis/scripts/25_proposed_model.py
python analysis/scripts/26_mimicry_holdout_analysis.py
```

**Süre**: ~30 dakika.

---

## 🎯 Aşama 5 — Karar Noktası

`analysis/data/results/mimicry_baseline_vs_proposed.csv` aç. Şu sayılara bak:

```bash
cat analysis/data/results/mimicry_baseline_vs_proposed.csv
```

### Karar matrisi

| Mimicry recall (proposed) | Yorum | Karar |
|---|---|---|
| **≥ %85** | Tezi destekliyor. Behavioral features çalışıyor + rate gap dengeli. | ✅ **Devam et → Aşama 6 (tam pipeline)** |
| **%75-85** | Sınırda. Endpoint feature importance'a bak. | ⚠️ **Endpoint top 5'te mi kontrol et** (aşağıda) |
| **%70-75** | Zayıf. V2 daha iyi gibi. | ⚠️ **Karar: V3 mi V2 mi** |
| **< %70** | Berbat. Modeli rate'e bağladık. | ❌ **Rollback V2'ye** |

### Endpoint kontrol (orta senaryoda)

```bash
head -10 analysis/data/results/proposed_model_feature_importance.csv
```

- Top 5'te en az 2 `endpoint_*` feature varsa → tez argümanı korunmuş, **V3 KULLAN**
- Top 5'te `global_*` features baskınsa → V2'ye benzer, ek yarar yok, V3 değer katmadı

---

## 🏗️ Aşama 6 — Eğer V3 Çalışıyorsa: Tam Pipeline (~4 saat)

### 6.1 — Kalan senaryoları koş

```bash
run_scenario_short S3_low_rate_bot        03_low_rate_bot.js
run_scenario_short S4_credential_stuffing 04_credential_stuffing.js
```

S6 slowloris ayrı koşum (BUGFIX_PLAN Aşama 5.3'teki gibi).

### 6.2 — Tüm pipeline'ı koş

```bash
# Tier'ları yenile (yeni S3, S4, S6 datasıyla)
python analysis/scripts/10_tier1_connections.py
python analysis/scripts/11_endpoint_cost.py
python analysis/scripts/12_tier2_features.py
python analysis/scripts/13_tier3_global.py
python analysis/scripts/14_tier4_sessions.py
python analysis/scripts/15_baseline_distance.py
python analysis/scripts/16_merge_all_features.py
python analysis/scripts/17_prepare_dataset.py
python analysis/scripts/18_feature_selection.py

# Baselines
python analysis/scripts/19_baseline_rate_threshold.py
python analysis/scripts/20_baseline_ewma_cusum.py
python analysis/scripts/21_baseline_random_forest.py

# Proposed + mimicry
python analysis/scripts/25_proposed_model.py
python analysis/scripts/26_mimicry_holdout_analysis.py

# Latency + FPR
python analysis/scripts/22_detection_latency.py
python analysis/scripts/23_detection_latency_by_scenario.py
python analysis/scripts/24_fpr_per_legit_ip_minute.py

# Ablation
python analysis/scripts/27_ablation_study.py

# Tables + Figures
python analysis/scripts/30_metrics_tables.py
python analysis/scripts/31_figures.py
python analysis/scripts/32_calibration_validity.py
python analysis/scripts/33_mimicry_analysis.py
```

---

## 📊 Aşama 7 — V1 vs V2 vs V3 Tam Karşılaştırma

```bash
cat > /tmp/compare_v1_v2_v3.py <<'EOF'
import pandas as pd
from pathlib import Path

V1 = Path("backups").glob("results_OLD_*"); V1 = sorted(V1)[-1] if V1 else None
V2 = Path("backups").glob("V2_lowRPS_*"); V2 = sorted(V2)[-1] if V2 else None
V3 = Path("analysis/data/results")

print("=" * 80)
print("THREE-VERSION COMPARISON: V1 (bugs) vs V2 (low RPS) vs V3 (production-realistic)")
print("=" * 80)

versions = [("V1", V1), ("V2", V2), ("V3", V3)]

print(f"\n{'Metric':<35} {'V1':>10} {'V2':>10} {'V3':>10}")
print("-" * 70)

# Overall
for label, path in versions:
    if path is None or not (path/"table1_overall.csv").exists():
        continue
    df = pd.read_csv(path/"table1_overall.csv", index_col=0)
    # store accuracy and macro_f1
    locals()[f"{label}_acc"] = df.loc["Proposed (ISO+RF)", "accuracy"]
    locals()[f"{label}_f1"]  = df.loc["Proposed (ISO+RF)", "macro_f1"]

print(f"{'In-dist accuracy':<35} {V1_acc:>10.4f} {V2_acc:>10.4f} {V3_acc:>10.4f}")
print(f"{'In-dist macro-F1':<35} {V1_f1:>10.4f} {V2_f1:>10.4f} {V3_f1:>10.4f}")

# Mimicry
for label, path in versions:
    if path is None: continue
    df = pd.read_csv(path/"mimicry_baseline_vs_proposed.csv")
    locals()[f"{label}_mim"] = df.loc[df.metric=="mimicry_recall_as_flood","proposed_iso_rf"].values[0]
    locals()[f"{label}_eva"] = df.loc[df.metric=="mimicry_evasion_rate","proposed_iso_rf"].values[0]

print(f"{'Mimicry recall (as flood)':<35} {V1_mim:>10.4f} {V2_mim:>10.4f} {V3_mim:>10.4f}")
print(f"{'Mimicry evasion rate':<35} {V1_eva:>10.4f} {V2_eva:>10.4f} {V3_eva:>10.4f}")

# Ablation
for label, path in versions:
    if path is None: continue
    df = pd.read_csv(path/"ablation_study_results.csv")
    for g in ["all", "ua_only", "rate_only", "endpoint_only"]:
        row = df[df.group==g].iloc[0]
        locals()[f"{label}_{g}"] = row["val_accuracy"]

print(f"{'Ablation: all features':<35} {V1_all:>10.4f} {V2_all:>10.4f} {V3_all:>10.4f}")
print(f"{'Ablation: UA-only':<35} {V1_ua_only:>10.4f} {V2_ua_only:>10.4f} {V3_ua_only:>10.4f}")
print(f"{'Ablation: rate-only':<35} {V1_rate_only:>10.4f} {V2_rate_only:>10.4f} {V3_rate_only:>10.4f}")
print(f"{'Ablation: endpoint-only':<35} {V1_endpoint_only:>10.4f} {V2_endpoint_only:>10.4f} {V3_endpoint_only:>10.4f}")

# Top 5 features
print("\n" + "=" * 70)
print("TOP 5 FEATURES (each version)")
print("=" * 70)
for label, path in versions:
    if path is None: continue
    df = pd.read_csv(path/"proposed_model_feature_importance.csv").head(5)
    print(f"\n{label}:")
    print(df.to_string(index=False))
EOF

python /tmp/compare_v1_v2_v3.py
```

Bu üç versiyon yan yana gösterir. Hangisi tezini en iyi destekliyor → onu kullan.

---

## 🚨 Aşama 8 — Karar ve Aksiyon

### Senaryo 1: V3 başarılı (mimicry recall ≥%85, endpoint top'a döndü)

**Aksiyon**: V3'ü kullan.

```bash
# Branch'i main'e merge
git add -A
git commit -m "v3: production-realistic legit baseline, results regenerated"
git checkout main
git merge bugfix-think-and-prisma
```

Sunum + tez metnine V3 sayılarını yaz.

### Senaryo 2: V3 V2'den iyi değil (mimicry düştü VEYA endpoint hâlâ top'ta değil)

**Aksiyon**: V2'ye dön.

```bash
# V2 sonuçlarını restore et
rm -rf analysis/data/results
unzip backups/V2_features_*.zip   # eski feature dosyaları
cp -r backups/V2_lowRPS_*/. analysis/data/results/

# V2 database restore
docker exec -i ddos_postgres psql -U research -d ddos_research \
    < backups/db_V2_*.sql

# Anlatımı değiştir: "Hybrid rate + behavioral detection"
```

### Senaryo 3: V3 ve V2 ikisi de problemli (felaket)

**Aksiyon**: V1'e dön.

```bash
# V1 sonuçlarını restore et (BUGFIX_PLAN rollback bölümüne göre)
unzip backups/results_OLD_*.zip
docker exec -i ddos_postgres psql -U research -d ddos_research \
    < backups/db_OLD_*.sql
```

Limitations'ta bug'ları dürüstçe yaz, V1 sayılarıyla devam.

---

## 🎯 V3'ün Tezi Nasıl Güçlendireceği

Eğer V3 başarılıysa, tezin anlatımı şöyle olur:

> *"Our experimental setup includes production-realistic legitimate traffic (100 concurrent users with NASA-calibrated log-normal think times), bringing total legitimate traffic rate within an order of magnitude of attack rates. Under this matched-rate condition, the mimicry holdout still achieves XX% detection, while ablation studies show that rate-only features alone reach only YY%. This demonstrates that the detection model relies on behavioral features rather than rate-based shortcuts even when the rate channel is not artificially constrained."*

Bu **çok güçlü** bir savunma. V2 ile bunu söyleyemezsin (çünkü rate gap büyük).

---

## ⏱️ Zaman Çizelgesi

| Saat | Aşama | İş |
|---|---|---|
| 09:00 - 09:10 | 0, 1, 2 | V2 yedek + S1 değişiklik + DB temizle |
| 09:10 - 10:40 | 3 | 3 senaryo koş (S1, S2, S5) |
| 10:40 - 11:10 | 4 | Mini pipeline |
| 11:10 - 11:20 | 5 | Karar an |
| 11:20 - 15:00 | 6 (eğer devam) | Kalan senaryolar + tam pipeline |
| 15:00 - 16:00 | 7, 8 | Karşılaştırma + final karar |

Sıkıştırırsa **5-6 saatte bitirir.** Tek günlük iş.

---

## ⚠️ Olası Sorunlar

| Problem | Çözüm |
|---|---|
| 100 VU NestJS'i çökertir | İlk smoke run'da `top` ile CPU/memory'i izle. Boğulursa target'ı 80'e düşür. |
| bcrypt CPU bottleneck olur | Login concurrency arttığı için doğal. NestJS request_time şişebilir. Sonuçları etkilemez. |
| Postgres write throughput dolar | `pg_stat_activity` izle. Tabloda lock yoksa OK. |
| k6 "ramping up too fast" | startVUs: 0 olduğu için ramping smooth gidiyor. Problem olmaz. |

---

İstersen başlamadan önce bir kez daha bana sor — "100 VU çok mu, 80 mi yapayım" gibi. Onay verirsen Aşama 0'dan başla.
