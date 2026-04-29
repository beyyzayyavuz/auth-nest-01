import re
import pandas as pd
from pathlib import Path
from datetime import datetime

# Script'in olduğu yerin parent'ı = analysis/ — nereden çağrılırsa çalışsın
ROOT = Path(__file__).resolve().parents[1]

# Dataset registry — Calgary path-level cross-trace için, NASA Aug95
# session-level cross-validation için kullanılacak
DATASETS = {
    'nasa_jul95': ROOT / 'data/raw/NASA_access_log_Jul95',
    'nasa_aug95': ROOT / 'data/raw/NASA_access_log_Aug95',
    'calgary':    ROOT / 'data/raw/calgary_access_log',
}

OUT = ROOT / 'data/parsed'
OUT.mkdir(parents=True, exist_ok=True)

LOG_PATTERN = re.compile(
    r'(?P<host>\S+)\s+'
    r'\S+\s+\S+\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+(?P<proto>\S+))?"\s+'
    r'(?P<status>\d+|-)\s+'
    r'(?P<bytes>\d+|-)'
)

def parse_line(line):
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    try:
        ts = datetime.strptime(d['ts'].split()[0], '%d/%b/%Y:%H:%M:%S')
    except ValueError:
        return None
    return {
        'host': d['host'],
        'timestamp': ts,
        'method': d['method'],
        'path': d['path'],
        'status': int(d['status']) if d['status'].isdigit() else None,
        'bytes': int(d['bytes']) if d['bytes'].isdigit() else 0,
    }

def parse_dataset(name, path):
    print(f'\n=== Parsing {name} ({path}) ===')
    if not path.exists():
        print(f'  SKIP: file not found')
        return None
    records = []
    with open(path, 'r', encoding='latin-1') as f:
        for i, line in enumerate(f):
            rec = parse_line(line)
            if rec:
                records.append(rec)
            if i % 200000 == 0 and i > 0:
                print(f'  ... {i:,} lines')
    print(f'  Parsed {len(records):,} valid records')

    df = pd.DataFrame(records)
    df = df.sort_values('timestamp').reset_index(drop=True)

    out_path = OUT / f'{name}.parquet'
    df.to_parquet(out_path, compression='snappy')
    print(f'  Saved {out_path}')

    print(f'  Time range: {df.timestamp.min()} → {df.timestamp.max()}')
    print(f'  Unique hosts: {df.host.nunique():,}')
    print(f'  Unique paths: {df.path.nunique():,}')
    print(f'  Method top: {df.method.value_counts().head(3).to_dict()}')
    print(f'  Status top: {df.status.value_counts().head(3).to_dict()}')

    return df

if __name__ == '__main__':
    for name, path in DATASETS.items():
        parse_dataset(name, path)
    print('\nAll datasets parsed.')