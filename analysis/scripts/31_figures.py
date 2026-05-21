"""
Day 23 — Tez figürleri.
Çıktı: analysis/data/results/figures/ altında PNG/PDF.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from sklearn.metrics import precision_recall_curve, confusion_matrix

plt.rcParams.update({
    'font.size': 11,
    'figure.dpi': 120,
    'savefig.dpi': 200,
    'figure.figsize': (8, 5),
})

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / 'data/results'
FIG = RESULTS / 'figures'
FIG.mkdir(parents=True, exist_ok=True)

# ============================================================
# Figür 1 — Cross-validation stability check
# ============================================================

# Load CV results
per_fold = pd.read_csv(RESULTS / "cross_validation_per_fold.csv")
summary = pd.read_csv(RESULTS / "cross_validation_summary.csv")

# Pull values
acc_mean = summary.loc[summary["metric"] == "accuracy", "mean"].values[0]
acc_std  = summary.loc[summary["metric"] == "accuracy", "std"].values[0]
f1_mean  = summary.loc[summary["metric"] == "macro_f1", "mean"].values[0]
f1_std   = summary.loc[summary["metric"] == "macro_f1", "std"].values[0]

# Plot style
plt.rcParams.update({
    "font.size": 11,
    "figure.dpi": 120,
    "savefig.dpi": 200,
    "axes.spines.top": False,
    "axes.spines.right": False,
})

fig, axes = plt.subplots(1, 2, figsize=(13, 5.5))

# ============================================================
# LEFT PANEL — per-fold accuracy bars + mean line
# ============================================================
ax = axes[0]
folds = per_fold["fold"].astype(int)
accs = per_fold["accuracy"]

colors = ["#1E2761"] * 5  # navy
bars = ax.bar(folds, accs, color=colors, alpha=0.85,
              edgecolor="#131A47", linewidth=1.2, width=0.6)

# Mean line
ax.axhline(acc_mean, color="#F96167", linestyle="--",
           linewidth=2, label=f"Mean = {acc_mean:.4f}", zorder=5)

# Std band
ax.axhspan(acc_mean - acc_std, acc_mean + acc_std,
           alpha=0.15, color="#F96167",
           label=f"± Std ({acc_std:.4f})")

# Annotate each bar
for bar, acc in zip(bars, accs):
    ax.text(bar.get_x() + bar.get_width() / 2, acc + 0.0001,
            f"{acc:.4f}", ha="center", va="bottom",
            fontsize=10, color="#1E2761", fontweight="bold")

# Y-axis tight zoom (since all values are near 1.0)
y_min = min(accs.min(), acc_mean - acc_std) - 0.0005
y_max = max(accs.max(), acc_mean + acc_std) + 0.0008
ax.set_ylim(y_min, y_max)

ax.set_xticks(folds)
ax.set_xlabel("Fold", fontsize=12)
ax.set_ylabel("Accuracy", fontsize=12)
ax.set_title("5-Fold Cross-Validation — Per-Fold Accuracy",
             fontsize=13, color="#1E2761", fontweight="bold", pad=12)
ax.legend(loc="lower right", framealpha=0.95, fontsize=10)
ax.grid(axis="y", alpha=0.3, linestyle=":")

# ============================================================
# RIGHT PANEL — summary metrics comparison
# ============================================================
ax = axes[1]

metrics = ["Accuracy", "Macro-F1", "Weighted-F1"]
means = [
    summary.loc[summary["metric"] == "accuracy", "mean"].values[0],
    summary.loc[summary["metric"] == "macro_f1", "mean"].values[0],
    summary.loc[summary["metric"] == "weighted_f1", "mean"].values[0],
]
stds = [
    summary.loc[summary["metric"] == "accuracy", "std"].values[0],
    summary.loc[summary["metric"] == "macro_f1", "std"].values[0],
    summary.loc[summary["metric"] == "weighted_f1", "std"].values[0],
]
colors_r = ["#1E2761", "#2B3A8C", "#02C39A"]

bars = ax.bar(metrics, means, yerr=stds, color=colors_r, alpha=0.85,
              capsize=10, edgecolor="black", linewidth=1.2, width=0.55,
              error_kw={"linewidth": 1.8, "ecolor": "#F96167"})

# Annotate
for bar, m, s in zip(bars, means, stds):
    ax.text(bar.get_x() + bar.get_width() / 2,
            m + s + 0.00015,
            f"{m:.4f}\n± {s:.4f}",
            ha="center", va="bottom",
            fontsize=10, color="#1E2761", fontweight="bold")

ax.set_ylim(0.997, 1.0012)
ax.set_ylabel("Score (mean across 5 folds)", fontsize=12)
ax.set_title("5-Fold CV — Summary Metrics (Mean ± Std)",
             fontsize=13, color="#1E2761", fontweight="bold", pad=12)
ax.grid(axis="y", alpha=0.3, linestyle=":")

# Overall figure title
fig.suptitle(
    "Cross-Validation Stability Check — Proposed Random Forest Model",
    fontsize=14, color="#131A47", fontweight="bold", y=1.02,
)

plt.tight_layout()
plt.savefig(FIG / "fig1_cross_validation.png", bbox_inches="tight")
plt.savefig(FIG / "fig1_cross_validation.pdf", bbox_inches="tight")
plt.close()
print('Saved fig1_cross_validation')



# ============================================================
# Figür 2 — Mimicry holdout prediction distribution
# ============================================================

table4 = pd.read_csv(RESULTS / 'table4_mimicry_holdout.csv', index_col=0)
fig, ax = plt.subplots(figsize=(9, 5))
table4.plot(kind='bar', ax=ax, width=0.7)
ax.set_xlabel('Predicted class')
ax.set_ylabel('Fraction')
ax.set_title('Mimicry Holdout — Prediction Distribution\n(true class is mimicry_flood, never seen during training)')
ax.legend(title='Model')
plt.xticks(rotation=30, ha='right')
plt.tight_layout()
plt.savefig(FIG / 'fig2_mimicry_holdout.png')
plt.savefig(FIG / 'fig2_mimicry_holdout.pdf')
plt.close()
print('Saved fig2_mimicry_holdout')

# ============================================================
# Figür 3 — Per-class PR-AUC
# ============================================================

table3 = pd.read_csv(RESULTS / 'table3_pr_auc.csv')
fig, ax = plt.subplots(figsize=(9, 5))
x = np.arange(len(table3))
ax.bar(x - 0.2, table3['PR_AUC_baseline'], 0.4, label='Baseline RF')
ax.bar(x + 0.2, table3['PR_AUC_proposed'], 0.4, label='Proposed (ISO+RF)')
ax.set_xticks(x)
ax.set_xticklabels(table3['class'], rotation=20, ha='right')
ax.set_ylabel('PR-AUC')
ax.set_title('Per-class PR-AUC — Baseline vs Proposed')
ax.legend()
ax.set_ylim(0, 1.02)
plt.tight_layout()
plt.savefig(FIG / 'fig3_pr_auc.png')
plt.savefig(FIG / 'fig3_pr_auc.pdf')
plt.close()
print('Saved fig3_pr_auc')

# ============================================================
# Figür 4 — Feature importance (Proposed model)
# ============================================================

importance = pd.read_csv(RESULTS / 'proposed_model_feature_importance.csv')
importance = importance.sort_values('importance', ascending=True)

top_n = 20
top_importance = importance.tail(top_n)

plt.figure(figsize=(8, 8))
plt.barh(top_importance['feature'], top_importance['importance'])
plt.xlabel('Feature importance')
plt.title(f'Top {top_n} feature importances — Proposed ISO+RF')
plt.tight_layout()
plt.savefig(FIG / 'fig4_feature_importance.png')
plt.savefig(FIG / 'fig4_feature_importance.pdf')
plt.close()
print('Saved fig4_feature_importance')

# ============================================================
# Figür 5 — Class separation (boxplots) for key features
# ============================================================

df_split = pd.read_parquet(ROOT / 'data/features/dataset_split.parquet')
df_split = df_split[df_split['split'].isin(['train', 'val', 'test'])]

key_features = ['req_rate', 'iat_cv', 'endpoint_entropy', 'endpoint_cost_sum',
                'status_4xx_ratio', 'login_present_ratio']   # 6 panel → 2x3 grid
fig, axes = plt.subplots(2, 3, figsize=(15, 8))
for ax, feat in zip(axes.flatten(), key_features):
    if feat not in df_split.columns:
        continue
    sns.boxplot(data=df_split, x='label', y=feat, ax=ax, showfliers=False)
    ax.set_title(feat)
    ax.tick_params(axis='x', rotation=30)
    ax.set_xlabel('')

plt.suptitle('Class separation for key behavioral features')
plt.tight_layout()
plt.savefig(FIG / 'fig5_class_separation.png')
plt.savefig(FIG / 'fig5_class_separation.pdf')
plt.close()
print('Saved fig5_class_separation')

# ============================================================
# Figür 6 — Ablation results (Day 21'den)
# ============================================================

# Day 21 ablation çıktısını CSV olarak kaydetmiş olmalısın
# Eğer yoksa burada elle tablo oluştur
ablation_data = pd.read_csv(RESULTS / 'ablation_study_results.csv')

plot_cols = ['group', 'val_accuracy']
ablation_data = ablation_data[plot_cols].copy()

label_map = {
    'all': 'all features',
    'no_iat': 'no IAT',
    'no_endpoint': 'no endpoint',
    'no_connection': 'no connection',
    'no_global_or_baseline_dist': 'no global/baseline',
    'no_cost': 'no cost',
    'no_status': 'no status',
    'ua_only': 'UA only',
    'rate_only': 'rate only',
    'endpoint_only': 'endpoint only',
    'connection_only': 'connection only',
    'global_baseline_only': 'global/baseline only',
}

ablation_data['group'] = ablation_data['group'].map(label_map).fillna(ablation_data['group'])
fig, ax = plt.subplots(figsize=(9, 5))
ablation_data_sorted = ablation_data.sort_values('val_accuracy', ascending=True)
ax.barh(ablation_data_sorted['group'], ablation_data_sorted['val_accuracy'])
ax.set_xlabel('Validation accuracy')
ax.set_title('Ablation study — feature group importance')
ax.set_xlim(0, 1.02)
ax.axvline(x=0.20, color='red', linestyle='--', alpha=0.5, label='Class baseline (1/n)')
ax.legend()
plt.tight_layout()
plt.savefig(FIG / 'fig6_ablation.png')
plt.savefig(FIG / 'fig6_ablation.pdf')
plt.close()
print('Saved fig6_ablation')

print(f'\nAll figures saved to {FIG}')