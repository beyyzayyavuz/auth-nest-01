"""
Cross-trace consistency report.
Tezdeki Section 'Calibration Validity'in ham verisi.

1. Reads saved IAT, Zipf, and Markov baseline JSON files.
2. Prints cross-dataset comparison tables.
3. Calculates percentage differences and Markov pairwise differences.
4. Writes a final thesis-style interpretation.
5. Saves everything into consistency_report.txt.
"""

import json
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'data/baselines'

# Hangi dataset hangi analizde kullanıldı
SESSION_DATASETS = ['nasa_jul95', 'nasa_aug95', 'clarknet_aug28', 'clarknet_sep4']
ZIPF_DATASETS    = ['nasa_jul95', 'nasa_aug95', 'calgary', 'clarknet_aug28', 'clarknet_sep4']

lines = []

def emit(s=''):
    print(s)
    lines.append(s)

emit('=' * 70)
emit('CROSS-TRACE CONSISTENCY REPORT')
emit(f'Generated: {datetime.now(timezone.utc).isoformat()}')
emit('=' * 70)

# === IAT LOGNORMAL ===
emit('\n--- 1. IAT LOGNORMAL FIT (per-session, requires host info) ---')
emit('   Calgary excluded: anonymized to 2 hosts.\n')
emit(f'{"dataset":<18} {"μ_log":>8} {"σ_log":>8} {"mean(s)":>9} '
     f'{"median(s)":>10} {"p95(s)":>8} {"samples":>10}')
emit('-' * 75)

iat_data = {}
for ds in SESSION_DATASETS:
    path = OUT / f'{ds}_iat_params.json'
    if not path.exists():
        continue
    p = json.load(open(path))
    iat_data[ds] = p
    emit(f'{ds:<18} {p["mu_log"]:>8.3f} {p["sigma_log"]:>8.3f} '
         f'{p["mean"]:>9.2f} {p["median"]:>10.2f} {p["p95"]:>8.2f} '
         f'{p["sample_count"]:>10,}')

# Intra vs inter institutional consistency
def diff_pct(a, b):
    return abs(a - b) / max(abs(a), abs(b)) * 100 if max(abs(a), abs(b)) > 0 else 0

emit('\n   Intra-institutional consistency:')
emit(f'   NASA Jul vs Aug:      μ_log Δ={diff_pct(iat_data["nasa_jul95"]["mu_log"], iat_data["nasa_aug95"]["mu_log"]):.1f}%, '
     f'σ_log Δ={diff_pct(iat_data["nasa_jul95"]["sigma_log"], iat_data["nasa_aug95"]["sigma_log"]):.1f}%')
emit(f'   ClarkNet Aug vs Sep:  μ_log Δ={diff_pct(iat_data["clarknet_aug28"]["mu_log"], iat_data["clarknet_sep4"]["mu_log"]):.1f}%, '
     f'σ_log Δ={diff_pct(iat_data["clarknet_aug28"]["sigma_log"], iat_data["clarknet_sep4"]["sigma_log"]):.1f}%')
emit('\n   Inter-institutional comparison (NASA avg vs ClarkNet avg):')
nasa_mu = (iat_data["nasa_jul95"]["mu_log"] + iat_data["nasa_aug95"]["mu_log"]) / 2
clark_mu = (iat_data["clarknet_aug28"]["mu_log"] + iat_data["clarknet_sep4"]["mu_log"]) / 2
nasa_sg = (iat_data["nasa_jul95"]["sigma_log"] + iat_data["nasa_aug95"]["sigma_log"]) / 2
clark_sg = (iat_data["clarknet_aug28"]["sigma_log"] + iat_data["clarknet_sep4"]["sigma_log"]) / 2
emit(f'   μ_log: NASA={nasa_mu:.3f}, ClarkNet={clark_mu:.3f}, Δ={diff_pct(nasa_mu, clark_mu):.1f}%')
emit(f'   σ_log: NASA={nasa_sg:.3f}, ClarkNet={clark_sg:.3f}, Δ={diff_pct(nasa_sg, clark_sg):.1f}%')

# === ZIPF ===
emit('\n--- 2. ZIPF ENDPOINT POPULARITY (path-level, all 5 datasets) ---\n')
emit(f'{"dataset":<18} {"α":>6} {"unique":>10} {"top-1%":>8} '
     f'{"top-10%":>9} {"top-100%":>10}')
emit('-' * 65)

zipf_data = {}
for ds in ZIPF_DATASETS:
    path = OUT / f'{ds}_zipf_params.json'
    if not path.exists():
        continue
    p = json.load(open(path))
    zipf_data[ds] = p
    emit(f'{ds:<18} {p["alpha"]:>6.2f} {p["unique_endpoints"]:>10,} '
         f'{p["top_1_share"]*100:>7.2f}% {p["top_10_share"]*100:>8.2f}% '
         f'{p["top_100_share"]*100:>9.2f}%')

emit('\n   Intra-institutional consistency:')
emit(f'   NASA Jul vs Aug:      α Δ={diff_pct(zipf_data["nasa_jul95"]["alpha"], zipf_data["nasa_aug95"]["alpha"]):.1f}%')
emit(f'   ClarkNet Aug vs Sep:  α Δ={diff_pct(zipf_data["clarknet_aug28"]["alpha"], zipf_data["clarknet_sep4"]["alpha"]):.1f}%')

# === MARKOV ===
emit('\n--- 3. MARKOV TRANSITION CROSS-TRACE PAIRWISE |DIFF| ---')
emit('   (Calgary excluded: anonymization precludes session-aware Markov)\n')

import pandas as pd

mat = {}
for ds in SESSION_DATASETS:
    path = OUT / f'{ds}_markov_transitions.json'
    if not path.exists():
        continue
    mat[ds] = pd.DataFrame(json.load(open(path))).T.fillna(0)

emit(f'{"pair":<48} {"max":>8} {"mean":>8}')
emit('-' * 64)
names = list(mat.keys())
for i in range(len(names)):
    for j in range(i+1, len(names)):
        a, b = mat[names[i]], mat[names[j]]
        common_idx = a.index.intersection(b.index)
        common_col = a.columns.intersection(b.columns)
        d = (a.loc[common_idx, common_col] - b.loc[common_idx, common_col]).abs()
        emit(f'{names[i]+" vs "+names[j]:<48} {d.values.max():>8.3f} {d.values.mean():>8.3f}')

# === FINAL NARRATIVE ===
emit('\n--- 4. STRUCTURAL-VS-CONTEXT SEPARATION (thesis findings) ---\n')

emit('   Three independent measurements support the structural-prior framing:')
emit('')
emit('   IAT (lognormal):')
emit('     - σ_log invariant across institutions (~%9 spread, structural)')
emit('     - μ_log context-dependent (~%24 inter-inst, ~%1-10 intra-inst)')
emit('')
emit('   Zipf (endpoint popularity):')
emit('     - Power-law shape universal (5/5 traces fit)')
emit('     - α value context-dependent (NASA 1.25, ClarkNet 0.95, Calgary 0.84)')
emit('')
emit('   Markov (navigation transitions):')
emit('     - Intra-institutional mean |diff|: ~0.013')
emit('     - Inter-institutional mean |diff|: ~0.080 (6x higher)')
emit('     - Same categorical structure (html/image/cgi/etc.) applies universally')
emit('')
emit('   Conclusion: distribution shapes (lognormal, power-law, transition')
emit('   structure) transfer as structural priors. Numerical parameters')
emit('   (μ_log, α, transition probabilities) require deployment-context')
emit('   re-parameterization.')

emit('\n' + '=' * 70)

# Save to file
report_path = OUT / 'consistency_report.txt'
with open(report_path, 'w') as f:
    f.write('\n'.join(lines))
print(f'\nReport saved to {report_path}')