"""
CIC-DDoS2019 external probe.

Amaç:
- analysis/data/external/cicddos2019 altında CSV veya Parquet dosyası var mı bakmak
- Kolonları görmek
- Label kolonunu bulmak
- Benign/attack dağılımını çıkarmak
- Bizim application-layer feature setimizle CIC feature-space uyumunu anlamak

Bu script final validation yapmaz; sadece feasibility/probe içindir.
"""

import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CIC_DIR = ROOT / "data/external/cicddos2019"
OUT = ROOT / "data/results/cic_external"
OUT.mkdir(parents=True, exist_ok=True)

print(f"Looking for CIC files in: {CIC_DIR}")

data_files = sorted(
    list(CIC_DIR.glob("*.csv")) +
    list(CIC_DIR.glob("*.parquet"))
)

if not data_files:
    print("\nNo CSV or Parquet files found.")
    print("Put CIC-DDoS2019 files under:")
    print(CIC_DIR)
    raise SystemExit(0)

print("\nFound data files:")
for f in data_files:
    print(f" - {f.name} ({f.stat().st_size / (1024 * 1024):.2f} MB)")

# İlk dosyadan başla
data_path = data_files[0]
print(f"\nReading sample file: {data_path.name}")

if data_path.suffix == ".parquet":
    df = pd.read_parquet(data_path)
    if len(df) > 200_000:
        df = df.sample(200_000, random_state=42)
else:
    df = pd.read_csv(data_path, nrows=200_000, low_memory=False)

# Kolon isimlerini temizle
df.columns = [str(c).strip() for c in df.columns]

print("\nShape:")
print(df.shape)

print("\nColumns:")
for c in df.columns:
    print(f" - {c}")

# Label kolonunu bul
possible_label_cols = ["Label", "label", "Class", "class", "Attack", "attack", "target", "Target"]
label_col = None

for c in possible_label_cols:
    if c in df.columns:
        label_col = c
        break

if label_col is None:
    print("\nCould not find label column automatically.")
    print("Inspect columns above and tell me which one is the label.")
    raise SystemExit(0)

print(f"\nDetected label column: {label_col}")

print("\nLabel distribution:")
label_counts = df[label_col].value_counts(dropna=False)
print(label_counts)

label_counts.to_csv(OUT / "cic_label_distribution_sample.csv")

# Numeric columns
numeric_cols = df.select_dtypes(include=["number", "bool"]).columns.tolist()

print(f"\nNumeric columns: {len(numeric_cols)}")
print(numeric_cols[:100])

# Missing check
if numeric_cols:
    missing = df[numeric_cols].isna().mean().sort_values(ascending=False).head(20)
    print("\nTop missing numeric columns:")
    print(missing)

# Common CICFlowMeter feature candidates
candidate_features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "Average Packet Size",
]

available_candidates = [c for c in candidate_features if c in df.columns]

print("\nAvailable common CIC features:")
for c in available_candidates:
    print(f" - {c}")

summary = {
    "file": data_path.name,
    "rows_sampled": len(df),
    "columns": len(df.columns),
    "label_col": label_col,
    "numeric_columns": len(numeric_cols),
    "available_candidate_features": ",".join(available_candidates),
}

pd.DataFrame([summary]).to_csv(OUT / "cic_probe_summary.csv", index=False)

print(f"\nSaved probe outputs to: {OUT}")