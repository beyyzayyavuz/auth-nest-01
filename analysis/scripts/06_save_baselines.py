"""
Tüm fit parametrelerini CalibrationBaseline tablosuna yaz.
Calgary: sadece zipf (path-only). Diğerleri: iat + zipf + markov + initial.

1. Reads baseline JSON files.
2. Decides which fitting method was used.
3. Inserts each baseline into PostgreSQL.
4. Updates existing rows if they already exist.
5. Saves everything into the CalibrationBaseline table.
"""

import json
import psycopg2
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'data/baselines'

DATASETS_META = {
    'nasa_jul95':     'NASA_HTTP_1995_07',
    'nasa_aug95':     'NASA_HTTP_1995_08',
    'calgary':        'Calgary_HTTP_1994_1995',
    'clarknet_aug28': 'ClarkNet_HTTP_1995_Aug28',
    'clarknet_sep4':  'ClarkNet_HTTP_1995_Sep04',
}

DATASET_BASELINES = {
    'nasa_jul95':     ['iat_params', 'zipf_params', 'markov_transitions', 'markov_initial'],
    'nasa_aug95':     ['iat_params', 'zipf_params', 'markov_transitions', 'markov_initial'],
    'calgary':        ['zipf_params'],
    'clarknet_aug28': ['iat_params', 'zipf_params', 'markov_transitions', 'markov_initial'],
    'clarknet_sep4':  ['iat_params', 'zipf_params', 'markov_transitions', 'markov_initial'],
}

conn = psycopg2.connect(
    host='localhost', port=5432, user='research', password='research',
    database='ddos_research',
)
cur = conn.cursor()

count = 0
for ds_name, source_label in DATASETS_META.items():
    for kind in DATASET_BASELINES[ds_name]:
        path = OUT / f'{ds_name}_{kind}.json'
        if not path.exists():
            print(f'SKIP {path} — not found')
            continue
        with open(path) as f:
            params = json.load(f)
        baseline_name = f'{ds_name}_{kind}'
        method = ('mle' if 'iat' in kind else
                  'log_log_regression' if 'zipf' in kind else
                  'frequency_count')
        cur.execute("""
            INSERT INTO "CalibrationBaseline"
                (name, "sourceDataset", parameters, "fitQuality", "createdAt")
            VALUES (%s, %s, %s::jsonb, %s::jsonb, %s)
            ON CONFLICT (name) DO UPDATE
                SET parameters = EXCLUDED.parameters,
                    "fitQuality" = EXCLUDED."fitQuality",
                    "createdAt" = EXCLUDED."createdAt"
        """, (
            baseline_name, source_label,
            json.dumps(params),
            json.dumps({'method': method}),
            datetime.utcnow(),
        ))
        count += 1

conn.commit()
cur.close()
conn.close()
print(f'{count} baselines saved to CalibrationBaseline table.')