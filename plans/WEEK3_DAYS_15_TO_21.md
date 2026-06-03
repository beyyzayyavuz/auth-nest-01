# Week 3 — Days 15 to 21 Implementation Guide

WEEK1 (calibration) ve WEEK2 (orchestration + Tier1-2 pipeline) tamamlandı.

**Eldeki çıktılar:**
- 502K+ RequestLog, 15K+ Connection, 12K+ Tier2 feature row
- 6 scenario (S1-S6) + recovery'leri, S6 sinyali pipeline'a taşındı
- 4-quartile EndpointCostProfile
- Random-label permutation: real=0.979, permuted=0.277, diff=0.702 (no leakage)

**Week 3 hedefi:** Detection model'i kurmak, baseline'larla karşılaştırmak, mimicry holdout deneyini yapmak, external validation almak.

> Tüm komutlar projenin kök dizininde çalıştırılır.

---

## Class taxonomy — Week 3'te kullanılacak label scheme

WindowLabel tablosunda şu label'lar var:

| Class | Source scenarios | Train mı Test mi |
|---|---|---|
| `normal_user` | S1, S2-S6 legit kısımları, recovery'ler | Train + Test |
| `http_flood` | S2 attack | Train + Test |
| `low_rate_bot` | S3 attack | Train + Test |
| `credential_stuffing` | S4 attack | Train + Test |
| `slow_http` | S6 attack (slowloris/slow_post) | Train + Test |
| `mimicry_flood` | S5 attack | **TEST-ONLY (HOLDOUT)** |

**5 class supervised** (normal + 4 attack), **mimicry_flood ayrı holdout**. Bu, Day 17'deki mimicry-holdout deneyinin temeli.

`S6_slowloris_broken*` ve `S6_slowloris_slowonly*` data'ları Week 2 retry artifaktları — bunları Week 3'te **DAHIL ETME** veya **legitimate olarak değerlendirme**, modelde karışıklık yaratmasın. Day 16 label generation'da explicit filter ekleyeceğiz.

---

## DAY 15 — Tier 3 (global) + Tier 4 (session) features + baseline-distance features

**Hedef:** Mevcut Tier 2 feature setine ek 4 boyut ekle:
1. **Tier 3 — Global window features:** Sistem genelinde concurrent connection, distinct IP, vs.
2. **Tier 4 — Session features:** sessionIdHash bazlı session-level metrikler
3. **Markov log-likelihood:** NASA-trained transition matrix vs gözlemlenen sequence
4. **IAT KS distance:** NASA empirical CDF'e karşı window IAT KS distance

**Toplam süre:** 5-6 saat

### 15.1 Tier 3 — Global window features

`analysis/scripts/13_tier3_global.py`:

```python
"""
Tier 3: Sistem geneli (per-window, all sources aggregated) feature'lar.
Per-window: tüm scenario boyunca o 10s window'da neler oldu sistem genelinde.
"""

import psycopg2
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'data/features'

WINDOW_SEC = 10

conn = psycopg2.connect(
    host='localhost', port=5432, user='research', password='research',
    database='ddos_research',
)

print('Loading RequestLog for Tier 3 global aggregation...')
req = pd.read_sql("""
    SELECT timestamp, ip, "ipSubnet24", "scenarioId", "trafficLabel"
    FROM "RequestLog" WHERE "scenarioId" IS NOT NULL
""", conn)
req['timestamp'] = pd.to_datetime(req['timestamp'], utc=True)
req['bucket_10s'] = req['timestamp'].dt.floor(f'{WINDOW_SEC}s')

print(f'  {len(req):,} requests')

# Per-window global aggregates
global_df = req.groupby(['scenarioId', 'bucket_10s']).agg(
    global_unique_ip=('ip', pd.Series.nunique),
    global_unique_subnet=('ipSubnet24', pd.Series.nunique),
    global_request_count=('timestamp', 'count'),
).reset_index()

global_df['global_req_rate'] = global_df['global_request_count'] / WINDOW_SEC
global_df.rename(columns={
    'scenarioId': 'scenario_id',
    'bucket_10s': 'window_start',
}, inplace=True)

# new_src_ratio: window'daki source'ların ne kadarı previously unseen
# (önceki window'a göre yeni IP)
print('Computing new_src_ratio...')
seen_ips = {}  # scenario_id → set of seen IPs
new_src = []
for _, row in global_df.iterrows():
    sid = row['scenario_id']
    ts = row['window_start']
    if sid not in seen_ips:
        seen_ips[sid] = set()
    # Bu window'daki IP'leri al
    window_ips = set(req[
        (req['scenarioId'] == sid) & (req['bucket_10s'] == ts)
    ]['ip'].unique())
    new_count = len(window_ips - seen_ips[sid])
    total_count = len(window_ips)
    new_src.append(new_count / total_count if total_count > 0 else 0)
    seen_ips[sid] |= window_ips

global_df['global_new_src_ratio'] = new_src

print(f'  {len(global_df):,} (scenario, window) global feature rows')
global_df.to_parquet(OUT / 'tier3_global.parquet', compression='snappy')
print(f'Saved tier3_global.parquet')
conn.close()
```

```bash
python analysis/scripts/13_tier3_global.py
```

### 15.2 Tier 4 — Session features

`analysis/scripts/14_tier4_sessions.py`:

```python
"""
Tier 4: Per-session features. sessionIdHash varsa (auth flow), session
düzeyinde metrikler.
"""

import psycopg2
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'data/features'

conn = psycopg2.connect(
    host='localhost', port=5432, user='research', password='research',
    database='ddos_research',
)

print('Loading RequestLog with session info...')
req = pd.read_sql("""
    SELECT timestamp, "sessionIdHash", "scenarioId", "routeTemplate",
           "responseTimeMs", "loginPresent"
    FROM "RequestLog"
    WHERE "scenarioId" IS NOT NULL
      AND "sessionIdHash" IS NOT NULL AND "sessionIdHash" != ''
""", conn)
req['timestamp'] = pd.to_datetime(req['timestamp'], utc=True)
print(f'  {len(req):,} session-tagged requests')

session_df = req.groupby(['scenarioId', 'sessionIdHash']).agg(
    request_count=('timestamp', 'count'),
    duration_sec=('timestamp', lambda x: (x.max() - x.min()).total_seconds()),
    unique_endpoints=('routeTemplate', pd.Series.nunique),
    mean_response_time=('responseTimeMs', 'mean'),
    login_count=('loginPresent', 'sum'),
).reset_index()

session_df['endpoints_per_request'] = (
    session_df['unique_endpoints'] / session_df['request_count']
)
session_df['requests_per_second'] = session_df.apply(
    lambda r: r['request_count'] / r['duration_sec'] if r['duration_sec'] > 0 else 0,
    axis=1,
)

session_df.rename(columns={'scenarioId': 'scenario_id'}, inplace=True)

print(f'  {len(session_df):,} sessions')
session_df.to_parquet(OUT / 'tier4_sessions.parquet', compression='snappy')
print(f'Saved tier4_sessions.parquet')

# Per-window session features (per (scenario, ip, window_10s))
# session_count, session_mean_duration, session_mean_request_count
# Bu kısım Day 16 merge'ine bırakıldı.
conn.close()
```

```bash
python analysis/scripts/14_tier4_sessions.py
```

### 15.3 Markov log-likelihood + IAT KS distance

NASA calibration baseline'larını kullanan derived feature'lar.

`analysis/scripts/15_baseline_distance.py`:

```python
"""
Per-window:
- markov_log_likelihood: NASA-trained transition matrix'e göre window'daki
  endpoint sequence'ının log-likelihood'u
- iat_ks_distance: window IAT distribution vs NASA empirical CDF KS distance
"""

import psycopg2
import json
import pandas as pd
import numpy as np
from pathlib import Path
from scipy.stats import ks_2samp

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'data/features'
BASELINES = ROOT / 'data/baselines'

WINDOW_SEC = 10

conn = psycopg2.connect(
    host='localhost', port=5432, user='research', password='research',
    database='ddos_research',
)

# Load NASA baselines
print('Loading NASA calibration baselines...')
nasa_iat_ecdf = pd.read_csv(BASELINES / 'nasa_jul95_iat_ecdf.csv')
nasa_markov = json.load(open(BASELINES / 'nasa_jul95_markov_transitions.json'))

# Endpoint kategorizasyonu (NASA Markov ile uyumlu)
def categorize_path(path):
    p = str(path).lower()
    if '/auth/' in p: return 'cgi'
    if '/user/profile' in p: return 'html'
    if '/user/search' in p: return 'cgi'
    if '/health' in p or '/ping' in p: return 'static'
    if '/metrics/' in p: return 'cgi'
    return 'other'

print('Loading RequestLog...')
req = pd.read_sql("""
    SELECT timestamp, ip, "ipSubnet24", "scenarioId", "routeTemplate"
    FROM "RequestLog" WHERE "scenarioId" IS NOT NULL
""", conn)
req['timestamp'] = pd.to_datetime(req['timestamp'], utc=True)
req['bucket_10s'] = req['timestamp'].dt.floor(f'{WINDOW_SEC}s')
req['category'] = req['routeTemplate'].apply(categorize_path)

# NASA IAT empirical CDF as numpy array (bin midpoints + percentile values)
nasa_iat_values = nasa_iat_ecdf['iat_sec'].values

def markov_ll(seq):
    """Sequence'in NASA Markov chain altında log-likelihood'u."""
    if len(seq) < 2: return 0.0
    ll = 0.0
    for i in range(len(seq) - 1):
        from_cat = seq[i]
        to_cat = seq[i + 1]
        prob = nasa_markov.get(from_cat, {}).get(to_cat, 1e-9)
        ll += np.log(max(prob, 1e-9))
    return ll / (len(seq) - 1)  # average per transition

def iat_ks(group_iats):
    """Group IAT'lerini NASA empirical CDF'e karşı KS distance."""
    if len(group_iats) < 5: return 0.0
    return float(ks_2samp(group_iats, nasa_iat_values).statistic)

# Per (scenario, key, window) feature
results = []
for key_col in ['ip', 'ipSubnet24']:
    print(f'\nComputing baseline distances by {key_col}...')
    grouped = req.groupby([key_col, 'bucket_10s', 'scenarioId'])
    n = 0
    for (k, b, sid), g in grouped:
        seq = g['category'].tolist()
        iats = g['timestamp'].diff().dt.total_seconds().dropna().values
        results.append({
            'aggregation_type': key_col,
            'aggregation_key': str(k),
            'window_start': b,
            'scenario_id': sid,
            'markov_log_likelihood': markov_ll(seq),
            'iat_ks_distance': iat_ks(iats[(iats > 0) & (iats < 1800)]),
        })
        n += 1
        if n % 5000 == 0:
            print(f'  {n:,} groups')

dist_df = pd.DataFrame(results)
print(f'\n{len(dist_df):,} baseline-distance rows')
dist_df.to_parquet(OUT / 'tier_baseline_distance.parquet', compression='snappy')
print(f'Saved tier_baseline_distance.parquet')
conn.close()
```

```bash
python analysis/scripts/15_baseline_distance.py
```

### 15.4 Merge tüm Tier feature'larını master DataFrame'e

`analysis/scripts/16_merge_all_features.py`:

```python
"""
Tier 2 + Tier 3 (global) + Tier 4 (session) + baseline distance feature'larını
tek bir master parquet'e birleştir.
"""

import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'data/features'

t2 = pd.read_parquet(OUT / 'tier2_features.parquet')
t3 = pd.read_parquet(OUT / 'tier3_global.parquet')
bd = pd.read_parquet(OUT / 'tier_baseline_distance.parquet')

print(f'T2: {len(t2):,} rows')
print(f'T3: {len(t3):,} rows')
print(f'BD: {len(bd):,} rows')

# Normalize types
for df in [t2, t3, bd]:
    df['scenario_id'] = df['scenario_id'].astype(str)
    df['window_start'] = pd.to_datetime(df['window_start'], utc=True)

# Merge T3 (global, per scenario+window) onto T2
master = t2.merge(t3, on=['scenario_id', 'window_start'], how='left')
print(f'After T3 merge: {len(master):,} rows')

# Merge baseline distance onto T2 (matching aggregation_type, key, window, scenario)
bd['aggregation_key'] = bd['aggregation_key'].astype(str)
master['aggregation_key'] = master['aggregation_key'].astype(str)
master = master.merge(
    bd, on=['aggregation_type', 'aggregation_key', 'window_start', 'scenario_id'],
    how='left'
)
print(f'After baseline-distance merge: {len(master):,} rows')

# Tier 4 session features per-window aggregation skip in v1
# (Future: per-(scenario, ip, window) session count from tier4_sessions)

# Fill NaN
fill_cols = ['global_unique_ip', 'global_unique_subnet', 'global_request_count',
             'global_req_rate', 'global_new_src_ratio',
             'markov_log_likelihood', 'iat_ks_distance']
for col in fill_cols:
    if col in master.columns:
        master[col] = master[col].fillna(0)

master.to_parquet(OUT / 'master_features.parquet', compression='snappy')
print(f'\nSaved master_features.parquet ({len(master):,} rows, {len(master.columns)} columns)')

print('\n=== Feature columns ===')
print(master.columns.tolist())
```

```bash
python analysis/scripts/16_merge_all_features.py
```

### 15.5 Day 15 checkpoint

- [ ] `tier3_global.parquet` çıktı, `global_unique_ip`, `global_new_src_ratio` non-zero
- [ ] `tier4_sessions.parquet` çıktı (session istatistikleri)
- [ ] `tier_baseline_distance.parquet` çıktı, S5 mimicry'de markov_ll legit'tan farklı
- [ ] `master_features.parquet` final birleşik dataset
- [ ] Sanity:
```python
import pandas as pd
df = pd.read_parquet('analysis/data/features/master_features.parquet')
print(df.groupby('scenario_id')[
    ['global_unique_ip', 'markov_log_likelihood', 'iat_ks_distance']
].mean().round(3))
```

`git commit -am "Day 15: Tier 3+4 + baseline-distance features merged"`

---

## DAY 16 — Label scheme + cleanup + train/test split prep

**Hedef:** Master feature DataFrame'inden temiz, etiketlenmiş train/test set hazırla.
Mimicry holdout için ayır.

**Toplam süre:** 3-4 saat

### 16.1 Label scheme finalization

```python
# analysis/scripts/17_prepare_dataset.py
"""
Master feature DataFrame'i 5-class supervised problem için hazırla.
Mimicry holdout test-only.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'data/features'

print('Loading master features...')
df = pd.read_parquet(OUT / 'master_features.parquet')
print(f'  {len(df):,} rows')

# Filter out S6 retry artifacts (broken/slowonly) — sadece final S6 kalsın
df = df[~df['scenario_id'].str.contains('_broken|_slowonly', na=False)].copy()
print(f'  After S6 retry artifact removal: {len(df):,} rows')

# Recovery'leri normal_user etiketine çek (label normalize)
df.loc[df['scenario_id'].str.endswith('_recovery'), 'majority_label'] = 'normal_user'

# Class label normalization
def normalize_label(label):
    if pd.isna(label): return 'unknown'
    l = str(label).lower()
    if 'normal_user' in l: return 'normal_user'
    if 'mimicry' in l: return 'mimicry_flood'
    if 'flood' in l and 'mimicry' not in l: return 'http_flood'
    if 'low_rate' in l: return 'low_rate_bot'
    if 'credential' in l or 'stuffing' in l: return 'credential_stuffing'
    if 'slow' in l: return 'slow_http'
    return 'unknown'

df['label'] = df['majority_label'].apply(normalize_label)
df = df[df['label'] != 'unknown'].copy()
print(f'\nLabel distribution:')
print(df['label'].value_counts())

# Split: mimicry_flood holdout test-only
holdout = df[df['label'] == 'mimicry_flood'].copy()
in_dist = df[df['label'] != 'mimicry_flood'].copy()
print(f'\nIn-distribution: {len(in_dist):,}, Holdout (mimicry): {len(holdout):,}')

# Time-based train/val/test split on in_dist
in_dist = in_dist.sort_values('window_start').reset_index(drop=True)
n = len(in_dist)
train_end = int(n * 0.70)
val_end = int(n * 0.85)
in_dist['split'] = 'train'
in_dist.loc[train_end:val_end, 'split'] = 'val'
in_dist.loc[val_end:, 'split'] = 'test'

# Holdout: tamamı mimicry_test
holdout['split'] = 'mimicry_test'

final = pd.concat([in_dist, holdout], ignore_index=True)
final.to_parquet(OUT / 'dataset_split.parquet', compression='snappy')
print(f'\nSaved dataset_split.parquet')
print(final.groupby(['split', 'label']).size().unstack(fill_value=0))
```

```bash
python analysis/scripts/17_prepare_dataset.py
```

### 16.2 Day 16 checkpoint

- [ ] `dataset_split.parquet` final
- [ ] 4 split: train, val, test, mimicry_test
- [ ] Class imbalance kontrol et — train'de azınlık class'lar (low_rate_bot, slow_http) yeterli sample sayısına sahip mi (>50)
- [ ] Mimicry test isolated, train'e sızmamış

---

## DAY 17 — Train/test/holdout setup + feature selection

**Hedef:** Model train için temiz feature/label matrisleri. Feature selection (drop label-leaking columns).

**Toplam süre:** 2-3 saat

### 17.1 Feature selection rules

```python
# Drop list (label leakage riski yüksek):
DROP_COLS = [
    'scenario_id',           # label proxy
    'majority_label', 'label', 'split',  # target/meta
    'window_start', 'window_end',  # time
    'aggregation_key',       # IP'i unique tag yapar (overfit)
    # 'aggregation_type' kalsın (categorical feature)
]
```

### 17.2 Random-label permutation re-check (Day 14'te ilk kez yapıldı, tekrarla)

Master feature setiyle:

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
import pandas as pd

df = pd.read_parquet('analysis/data/features/dataset_split.parquet')
df = df[df['split'].isin(['train', 'val'])]

X = df.drop(columns=DROP_COLS, errors='ignore').select_dtypes(include=['number', 'bool'])
X = X.fillna(0)
y = df['label']

clf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
real = cross_val_score(clf, X, y, cv=3, scoring='accuracy').mean()
y_perm = y.sample(frac=1, random_state=42).reset_index(drop=True)
perm = cross_val_score(clf, X, y_perm, cv=3, scoring='accuracy').mean()
print(f'Real: {real:.3f}, Permuted: {perm:.3f}, Diff: {real-perm:.3f}')
# Diff > 0.4 olmalı; aksi halde leakage var
```

### 17.3 Day 17 checkpoint

- [ ] Feature columns listesi documented
- [ ] Random-label diff > 0.4 (master feature setinde de tutarlı)
- [ ] Train/val/test/mimicry_test arrays hazır

---

## DAY 18 — Baseline models

**Hedef:** 3 baseline kur. Tezdeki "proposed model X baseline'lardan iyi" iddiasının zemini.

**Toplam süre:** 5-6 saat

### 18.1 Baseline 1 — Per-IP rate threshold

Sadece `req_rate` feature'ı; threshold ile binary attack/legit (sonra multiclass extend).

```python
# Per-class threshold optimization
# req_rate'in p95'ini legit'ten al, threshold olarak kullan
# Üstüne çıkanları "attack" kabul et (binary)
```

### 18.2 Baseline 2 — Statistical (EWMA + CUSUM)

Per-IP `req_rate` üzerinde online change detection.

### 18.3 Baseline 3 — Random Forest (multiclass)

Tüm Tier 2-3-baseline_distance feature'ları, 5-class RF:

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

clf_rf = RandomForestClassifier(n_estimators=200, max_depth=None, random_state=42, n_jobs=-1)
clf_rf.fit(X_train, y_train)
y_pred = clf_rf.predict(X_val)
print(classification_report(y_val, y_pred))
```

### 18.4 Per-class metrics

PR-AUC her class için:

```python
from sklearn.preprocessing import label_binarize
from sklearn.metrics import precision_recall_curve, average_precision_score

classes = ['normal_user', 'http_flood', 'low_rate_bot',
           'credential_stuffing', 'slow_http']
y_val_bin = label_binarize(y_val, classes=classes)
y_score = clf_rf.predict_proba(X_val)
for i, c in enumerate(classes):
    ap = average_precision_score(y_val_bin[:, i], y_score[:, i])
    print(f'{c}: PR-AUC = {ap:.3f}')
```

### 18.5 Detection latency (post-hoc)

Test set sırasındaki "ilk doğru pozitif" zamanını saldırı başlangıcına göre hesapla.

### 18.6 Day 18 checkpoint

- [ ] 3 baseline çalışıyor, val accuracy raporlandı
- [ ] PR-AUC her class için
- [ ] Detection latency p50/p95
- [ ] FPR per legitimate IP per minute

---

## DAY 19 — Proposed model (stacked anomaly + supervised)

**Hedef:** Layer A (Isolation Forest, sadece legit'te train) + Layer B (RF, full feature + anomaly_score).

**Toplam süre:** 4-5 saat

### 19.1 Layer A — Isolation Forest

```python
from sklearn.ensemble import IsolationForest

X_train_legit = X_train[y_train == 'normal_user']
iso = IsolationForest(contamination=0.05, random_state=42)
iso.fit(X_train_legit)

# Anomaly score for all
X_train['anomaly_score'] = iso.decision_function(X_train.drop(columns=['anomaly_score'], errors='ignore'))
X_val['anomaly_score'] = iso.decision_function(X_val.drop(columns=['anomaly_score'], errors='ignore'))
X_mimicry['anomaly_score'] = iso.decision_function(X_mimicry.drop(columns=['anomaly_score'], errors='ignore'))
```

### 19.2 Layer B — RF on full + anomaly_score

```python
clf_proposed = RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1)
clf_proposed.fit(X_train, y_train)
```

### 19.3 Compare proposed vs RF baseline

| Metric | Baseline RF | Proposed | Diff |
|---|---|---|---|
| In-dist accuracy | X.XX | X.XX | ... |
| In-dist macro-F1 | X.XX | X.XX | ... |
| Mimicry recall | X.XX | X.XX | ... |

### 19.4 Day 19 checkpoint

- [ ] Proposed model trained, val performance reported
- [ ] Comparison table baseline vs proposed
- [ ] Mimicry holdout recall for both (asıl kritik)

---

## DAY 20 — External validation: CIC-DDoS2019 + Mimicry holdout analysis

**Hedef:** External validation (CIC subset) + ana mimicry holdout deney.

**Toplam süre:** 4-5 saat (CIC parse pahalı olabilir)

### 20.1 CIC-DDoS2019 external validation

CIC subset'i indir (HTTP flood + slow-rate). Feature'larını bizimkilere align et (eksiklere NaN). Evaluate proposed model.

### 20.2 Mimicry holdout deneyi (ASIL ANA SONUÇ)

```python
# Train on in-dist (no mimicry)
clf.fit(X_train, y_train)

# Test on in-dist
y_pred_indist = clf.predict(X_test)
print(f'In-dist accuracy: {(y_pred_indist == y_test).mean():.3f}')

# Test on mimicry holdout
y_pred_mimicry = clf.predict(X_mimicry)
# Mimicry'nin hangi class'a düştüğünü gör
print(f'\nMimicry predictions distribution:')
print(pd.Series(y_pred_mimicry).value_counts(normalize=True))

# Mimicry "http_flood" olarak doğru sınıflanma oranı (mimicry aslında flood'un mimicry varyantı)
mimicry_recall_as_flood = (y_pred_mimicry == 'http_flood').mean()
print(f'Mimicry recall as http_flood: {mimicry_recall_as_flood:.3f}')

# Mimicry "normal_user" olarak yanlış sınıflanma (legit gibi geçti)
mimicry_evasion_rate = (y_pred_mimicry == 'normal_user').mean()
print(f'Mimicry evasion rate (classified as normal): {mimicry_evasion_rate:.3f}')
```

**Bu sonuç tezindeki en kritik tablodur.** İki uç durum:

| Senaryo | mimicry_recall_as_flood | mimicry_evasion_rate | Yorum |
|---|---|---|---|
| Strong | >0.7 | <0.2 | Behavioral features mimicry'e dayanıklı |
| Expected | 0.3-0.6 | 0.2-0.5 | Behavioral kısmen koruyor, surface'a kısmen bağımlı |
| Weak | <0.3 | >0.5 | Detection mostly surface (UA/IP) tabanlı |

### 20.3 Day 20 checkpoint

- [ ] CIC external validation skoru (eğer parse başarılı)
- [ ] Mimicry recall vs in-dist recall fark
- [ ] Mimicry evasion rate

---

## DAY 21 — Week 3 checkpoint + ablation + decision

**Hedef:** Geri dönüp tüm Week 3 sonuçlarını sentezle. Ablation study yap. Panic mode kararı (gerekirse).

**Toplam süre:** 4-5 saat

### 21.1 Ablation — feature gruplarını sırayla kapat

```python
ablation_groups = {
    'all': all_features,
    'no_iat': [c for c in all_features if 'iat_' not in c],
    'no_endpoint': [c for c in all_features if 'endpoint_' not in c],
    'no_connection': [c for c in all_features if 'connection_' not in c
                      and 'partial_' not in c and 'timeout_' not in c],
    'no_global_or_baseline_dist': [c for c in all_features
                                    if 'global_' not in c and 'markov_' not in c
                                    and 'iat_ks' not in c],
    'ua_only': ['ua_unique', 'ua_entropy'],
    'ip_only': [c for c in all_features if 'ip' in c.lower()],
}
for name, cols in ablation_groups.items():
    clf.fit(X_train[cols], y_train)
    acc = clf.score(X_val[cols], y_val)
    print(f'{name}: val accuracy = {acc:.3f}')
```

**UA-only ablation kritik:** Eğer UA-only %85+ verirse → modelin asıl olarak UA'ya bağlı olduğu ortaya çıkar (mimicry holdout'ta zaten görülmüş olmalı).

### 21.2 Panic mode kararı

Eğer:
- Proposed model in-dist baseline'dan iyi DEĞİLSE
- Mimicry recall korkunç düşük (<0.1)
- Random-label permutation diff < 0.4

→ Week 4'te **negative result + ablation analysis** tezine pivot. Bu meşru bir akademik katkı.

Eğer iyiyse:
→ Week 4'te metrics yazımı + figürler + tez yazımı.

### 21.3 Day 21 / Week 3 checkpoint

- [ ] 3 baseline + proposed model trained
- [ ] In-dist ve mimicry holdout metrikleri
- [ ] CIC external validation (eğer mümkün olduysa, yoksa limitations'a yaz)
- [ ] Ablation tablosu (5+ feature group)
- [ ] Detection latency raporlandı
- [ ] Week 4 yazıma karar verildi (proposed model çalışıyor mu, panic pivot mu)

`git commit -am "Week 3 complete: detection models + mimicry holdout + ablation"`

---

## Risk register (Week 3'e özel)

| Risk | Olasılık | Etki | Mitigasyon |
|---|---|---|---|
| Class imbalance modelleri ezer | yüksek | orta | class_weight='balanced', focal loss, oversampling |
| Real label accuracy %95+ → "kolay dataset" şüphesi | orta | orta | Mimicry holdout asıl test; ablation UA/IP kontrol |
| CIC-DDoS2019 parse başarısız | orta | düşük | Atla, internal-only, limitations |
| Mimicry holdout recall = 0 | orta | yüksek (panic trigger) | Tezde "behavioral detection lab limits" diye dürüst yaz |
| Master feature merge'de NaN flooding | düşük | orta | Day 15 sanity'de fillna kontrolü |
| Memory error 502K request × 30+ feature | düşük | orta | dask veya per-scenario chunked processing |

---

## Hard rules (Week 3)

1. **Mimicry holdout'a SADECE test'te bak.** Train'e sızdırma. Cross-validation'da bile mimicry windows'unu dahil etme.
2. **Random-label permutation testi her major model train'i öncesi tekrarla.** Day 14'te %27.7 idi, Week 3 boyunca her test öncesi tekrar yap. Eğer 0.5'in üzerine çıkarsa data leakage var.
3. **Day 21 sonu Week 4 yazıma kararını ver:** detection iyi mi (yazıma geç) yoksa pivot mu (negative result).
4. **Per-class metrics ZORUNLU.** Aggregate accuracy yanıltıcı (%97 normal_user dominance). Macro-F1, per-class PR-AUC, FPR per legit IP/min.
5. **Panic mode hatırlat:** Detection sonuçları kötüyse modeli büyütmeye çalışma — analiz yaz.

---

## Week 3 sonu hedef tezde olması gerekenler

1. **Comparison table:** Baseline vs Proposed × 5 metric (Accuracy, Macro-F1, PR-AUC, FPR/IP/min, Detection latency)
2. **Mimicry holdout sonucu:** in-dist vs out-of-dist mimicry recall farkı (asıl thesis finding)
3. **Ablation table:** Feature group importance
4. **CIC external validation:** Sınırlı ama varsa skor
5. **Limitations:** Synthetic-only, single-app, lab-scale, no iterative adaptive adversary

Bu çıktılar Week 4'te tez yazımının iskeletini oluşturur. Day 22-25 metric/figure üretimi, Day 26-28 yazım.
