# Go find any text that looks like 3 digits in a row. (for instance Status: 200) = regular expression
import re
import pandas as pd
# + => /
from pathlib import Path
# 01/Jul/1995:00:00:01 -0400 => 1995-07-01 00:00:01
from datetime import datetime

# Script'in olduğu yerin parent'ı = analysis/ — nereden çağrılırsa çalışsın
# parents[0] = /Users/beyzayavuz/auth-nest-01/analysis/scripts
# parents[1] = /Users/beyzayavuz/auth-nest-01/analysis
# The script can work even if the project folder is moved.
ROOT = Path(__file__).resolve().parents[1]

# Dataset registry — Calgary path-level cross-trace için, NASA Aug95
# session-level cross-validation için kullanılacak
# Because the script can loop through all datasets automatically instead of parsing each one manually.
DATASETS = {
    'nasa_jul95':     ROOT / 'data/raw/NASA_access_log_Jul95',
    'nasa_aug95':     ROOT / 'data/raw/NASA_access_log_Aug95',
    'calgary':        ROOT / 'data/raw/calgary_access_log',
    'clarknet_aug28': ROOT / 'data/raw/clarknet_access_log_Aug28',
    'clarknet_sep4':  ROOT / 'data/raw/clarknet_access_log_Sep4',
}

# This defines the output folder. The parsed data will be saved here as parquet files.
OUT = ROOT / 'data/parsed'
# If the output folder doesn't exist, create it. This ensures that the script can run without errors even if the folder is missing.
OUT.mkdir(parents=True, exist_ok=True)

# ( = Start the box ?P< = "Hey Python, I am about to give this box a customized name..."host = "...and that name is host!"
# [1]\S+ = Put any non-space text inside this box.) = Close the box. 
# "Hey, read this text, but don't bother saving it in a box. Just throw it away."
# \S+: Matches the first dash (-) in your log.
# \s+: Skips the spaces after it.
# [^\]]+:rab every character inside the brackets until you hit the closing bracket]
# \d+: Looks for a number (digits). |: This vertical bar means "OR".
LOG_PATTERN = re.compile(
    r'(?P<host>\S+)\s+'
    r'\S+\s+\S+\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+(?P<proto>\S+))?"\s+'
    r'(?P<status>\d+|-)\s+'
    r'(?P<bytes>\d+|-)'
)

# Try to understand this log line using the regex pattern.
# groupdict = put the extracted log parts into a dictionary
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