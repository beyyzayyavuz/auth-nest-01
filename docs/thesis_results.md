# 4. Results

This chapter presents the experimental results of the proposed API-layer DDoS detection pipeline. The evaluation focuses on six main aspects: calibration reference comparison, in-distribution detection performance, mimicry holdout behavior, feature ablation, detection latency, and false positive rate. The main objective is to determine whether behavior-based features can detect DDoS traffic even when the attacker attempts to imitate surface-level legitimate characteristics.

All results in this chapter use the V3 experimental configuration, which corresponds to the bug-fixed implementation under production-realistic legitimate traffic volume (100 concurrent legitimate users with applied log-normal think times and corrected backend cost capture). Sensitivity analysis comparing V3 with the original (V1) and intermediate (V2) configurations is provided in Discussion §5.7 and Appendix A.

---

## 4.1 Calibration Reference Comparison

NASA web server traces were used as a calibration reference during the design of the legitimate traffic generator and baseline-distance features. The purpose of this comparison was not to exactly replay NASA traffic, but to evaluate how the final synthetic API traffic relates to a historical real-world web traffic reference.

Figure 7 compares the inter-arrival time (IAT) distribution of the synthetic legitimate traffic with the NASA Jul 1995 trace. Under the V3 configuration, with applied log-normal think times and production-realistic concurrent users, the resulting KS statistic was `KS = 0.321`, indicating a substantial improvement in distributional alignment compared with earlier configurations. The shape of the synthetic IAT distribution now closely follows the NASA distribution in the 0.1–10 second range, with the main divergence occurring in the long tail (>30 seconds) that reflects NASA's broader historical session structure.

[fig7_iat_calibration]

Figure 8 compares endpoint popularity using a Zipf-style rank-frequency plot. Both NASA and synthetic legitimate traffic show a decreasing rank-frequency trend. The synthetic API traffic has a steeper slope because the experimental API contains a much smaller and more constrained endpoint set. The synthetic endpoint popularity alpha was approximately `2.20`, while the NASA reference alpha was approximately `1.25`.

[fig8_zipf_calibration]

Overall, the calibration comparison shows that the generated legitimate traffic follows the structural assumptions of real web traffic — log-normal IAT shape and Zipf endpoint popularity — even though numerical parameters differ due to the smaller endpoint set and controlled session structure. This structural-vs-context separation is discussed further in Chapter 5.

---

## 4.2 Detection Performance

The first main evaluation compares the proposed Random Forest model trained on the multi-tier behavioral feature set against three baselines: per-IP rate threshold, EWMA/CUSUM statistical change detection, and a default Random Forest baseline. A semi-supervised extension stacking an Isolation Forest anomaly score (ISO+RF) is reported as an alternative.

Table 1 summarizes the overall in-distribution test performance.

**Table 1. Overall test performance (V3 configuration).**

| Model | Accuracy | Macro-F1 | Weighted-F1 |
|---|---:|---:|---:|
| Rate threshold baseline | 0.6542 | — | — |
| EWMA/CUSUM baseline | 0.5754 | — | — |
| Random Forest (proposed) | 1.0000 | 1.0000 | 1.0000 |
| ISO+RF (alternative) | 1.0000 | 1.0000 | 1.0000 |

The proposed Random Forest achieves perfect in-distribution accuracy on the four supervised classes (1446 test windows, zero misclassifications). The rate-threshold and EWMA/CUSUM baselines are well below the supervised models, achieving 65% and 58% accuracy respectively, with recall around 47% and 31% on the attack classes.

Table 2 shows the per-class metrics for the proposed model.

**Table 2. Per-class metrics for the proposed Random Forest model (test set).**

| Class | Precision | Recall | F1-score | Support |
|---|---:|---:|---:|---:|
| credential_stuffing | 1.0000 | 1.0000 | 1.0000 | 396 |
| http_flood | 1.0000 | 1.0000 | 1.0000 | 332 |
| low_rate_bot | 1.0000 | 1.0000 | 1.0000 | 145 |
| normal_user | 1.0000 | 1.0000 | 1.0000 | 573 |

All four supervised classes were classified with zero error on the test set. Figure 1 shows the confusion matrix of the proposed model on the in-distribution test set.

[fig1_confusion_matrix]

Table 3 reports the per-class PR-AUC values.

**Table 3. Per-class PR-AUC (test set).**

| Class | Random Forest | ISO+RF |
|---|---:|---:|
| credential_stuffing | 1.0000 | 1.0000 |
| http_flood | 1.0000 | 1.0000 |
| low_rate_bot | 1.0000 | 1.0000 |
| normal_user | 1.0000 | 1.0000 |

The PR-AUC values are perfect for all classes, indicating that the supervised models separate the in-distribution classes completely. A random-label permutation sanity check confirmed that this performance reflects genuine signal: real-label CV accuracy was 0.998 versus 0.330 under permuted labels (class baseline 0.25), a 66.9 percentage-point gap.

[fig3_pr_auc]

---

## 4.3 Mimicry Holdout Evaluation

The mimicry holdout evaluation is the key experiment in this study. The `mimicry_flood` scenario was excluded from training and validation. It was used only as a holdout test set with 1,299 windows. This design tests whether the model can detect attack behavior when the attacker attempts to imitate surface-level legitimate characteristics (User-Agent diversity, IP pool overlap, token reuse, sticky sessions).

Since `mimicry_flood` is not a training class, the model cannot directly predict that label. Three metrics are used:

- `mimicry_recall_as_flood`: fraction of mimicry windows predicted as `http_flood`,
- `mimicry_evasion_rate`: fraction of mimicry windows predicted as `normal_user`,
- `mimicry_binary_attack_recall`: fraction of mimicry windows predicted as any non-normal class.

Table 4 shows the mimicry holdout prediction distribution.

**Table 4. Mimicry holdout prediction distribution (V3 configuration).**

| Predicted class | Random Forest | ISO+RF (alternative) |
|---|---:|---:|
| http_flood | 0.9638 | 0.8891 |
| normal_user | 0.0308 | 0.1055 |
| low_rate_bot | 0.0054 | 0.0054 |

The proposed Random Forest classified `96.38%` of mimicry windows (1252 of 1299) as `http_flood`. Only `3.08%` of mimicry windows (40 of 1299) were classified as `normal_user`, and `0.54%` (7 of 1299) as `low_rate_bot`. The binary attack recall on the mimicry holdout is therefore `96.92%`.

The ISO+RF stacking extension produced lower mimicry recall (88.91%) than the supervised Random Forest alone, indicating that under V3 conditions the unsupervised anomaly layer does not contribute additional discriminative power; the supervised model with multi-tier features already captures the mimicry signal.

Figure 2 visualizes the mimicry prediction distribution.

[fig2_mimicry_holdout]

The result indicates that mimicry traffic was overwhelmingly mapped to the attack class `http_flood` rather than being accepted as legitimate traffic. This supports the central claim that behavior-based features can remain effective even when surface-level characteristics are made more realistic.

Figure 10 provides a focused breakdown of the proposed model's mimicry classifications.

[fig10_mimicry_breakdown]

The mimicry deep-dive analysis compares mimicry traffic with naive flood and legitimate traffic across key features. Figure 9 shows that mimicry traffic can resemble legitimate traffic in some surface-level dimensions but differs strongly in endpoint-level behavioral features such as endpoint entropy and endpoint cost. Mimicry traffic shows higher User-Agent entropy than both naive flood and legitimate traffic, reflecting the attacker's attempt to create surface-level diversity. However, the UA-only ablation performed near random (13.24% mimicry recall), confirming that the classifier does not rely primarily on User-Agent features.

[fig9_mimicry_features]

---

## 4.4 Ablation Study

The ablation study evaluates how different feature groups contribute to detection performance. Feature groups were removed or isolated, and the model was retrained under each condition. Both validation accuracy and mimicry recall are reported, since these metrics measure different aspects of detection capability: validation accuracy measures in-distribution separation, while mimicry recall measures generalization to an unseen attack variant.

Figure 6 summarizes the ablation results.

[fig6_ablation]

Table 5 presents the key ablation comparisons.

**Table 5. Ablation study results (V3 configuration).**

| Feature configuration | Val accuracy | Mimicry recall (as flood) | Mimicry evasion |
|---|---:|---:|---:|
| All features (37) | 1.0000 | 0.9638 | 0.0308 |
| No IAT | 0.9993 | 0.5312 | 0.4611 |
| No endpoint | 0.9993 | 0.7937 | 0.2009 |
| No connection | 0.9993 | 0.9384 | 0.0562 |
| No global/baseline | 0.9495 | 0.1493 | 0.8491 |
| No cost | 1.0000 | 0.9523 | 0.0423 |
| No status | 0.9993 | 0.9715 | 0.0231 |
| UA only | 0.3541 | 0.1324 | 0.8676 |
| Rate only | 0.9281 | 0.7313 | 0.0493 |
| Endpoint only | 0.8313 | 0.7159 | 0.0308 |
| Connection only | 0.2794 | 0.5335 | 0.0000 |
| Global/baseline only | 0.9924 | 0.7221 | 0.0639 |

The ablation results carry the central methodological message of this thesis. The full feature set achieves 96.38% mimicry recall. The `rate_only` configuration recalls only 73.13% of mimicry windows as `http_flood`, even though it achieves 92.81% in-distribution validation accuracy. This 23 percentage-point gap is the contribution of behavioral features to mimicry detection — features that cannot be inferred from request volume alone.

The `ua_only` configuration recalls only 13.24% of mimicry windows, well below the class-baseline of 25%, demonstrating that the model does not use User-Agent features as a shortcut. Removing the IAT feature group drops mimicry recall by 43 percentage points (96.38% → 53.12%), demonstrating that inter-arrival-time irregularities remain a strong behavioral signal even under surface-level mimicry. Removing the global+baseline-distance feature group drops mimicry recall by 81 percentage points (96.38% → 14.93%), indicating that these features capture the distributed nature of attacks that local per-IP features cannot.

The convergence of these ablation results confirms that mimicry robustness arises from the combination of multiple behavioral feature groups rather than from any single feature category.

Figure 4 shows the top feature importances of the proposed Random Forest model.

[fig4_feature_importance]

The most important features included `global_unique_ip` (0.140), `global_unique_subnet` (0.116), `global_req_rate` (0.112), `endpoint_cost_mean` (0.086), `status_4xx_ratio` (0.083), `global_request_count` (0.082), `login_present_ratio` (0.074), `mean_cpu_time` (0.039), `iat_mean` (0.039), and `endpoint_cost_sum` (0.034). The high importance of global source-diversity features reflects the distributed nature of the attack scenarios, while the consistent presence of endpoint-cost, identity, and IAT features confirms that the model uses a combination of feature groups rather than relying on any single signal.

---

## 4.5 Detection Latency and False Positive Rate

Detection latency was computed using scenario-flow ordering. For each attack scenario, the first detected attack window was compared with the scenario start time.

Table 6 summarizes the scenario-level latency results.

**Table 6. Detection latency by scenario (V3 configuration).**

| Scenario | Expected label | Detected | Latency (sec) | Scenario recall |
|---|---|---:|---:|---:|
| S2_http_flood | http_flood | True | 0 | high |
| S3_low_rate_bot | low_rate_bot | True | 10 | moderate |
| S4_credential_stuffing | credential_stuffing | True | 0 | high |
| S5_mimicry_flood | mimicry_flood | True | 0 | 0.96 |
| S6_slowloris | slow_http | True | 0 | sparse* |

*Note:* The S6 slow HTTP result should be interpreted differently from the supervised attack classes. Although the first timeout-based signal appeared at the beginning of the scenario, slow HTTP behavior appeared as sparse Nginx timeout/partial-connection events rather than dense request-level windows. Therefore S6 is evaluated through a connection-level rule rather than as a supervised class. Discussion §5.3 provides further detail.

The median detection latency was `0.0` seconds (detection in the first 10-second window). The slowest detection was observed for the low-rate bot scenario, which was detected after 10 seconds — expected, because low-rate attacks are designed to be closer to normal behavior.

False positive behavior was measured on normal-user IP-level windows. The proposed Random Forest model produced `0` false positive windows across all normal-user IP-level windows. This corresponds to:

- window-level FPR: `0.0`
- FPR per legitimate IP-minute: `0.0`

This is an improvement over the original configuration (V1) in which the FPR was 0.018 per legitimate IP-minute. The combination of bug fixes and production-realistic legitimate traffic conditions produces a model that produces no false positives on legitimate user activity in this controlled experimental setting.

---

## 4.6 External Validation Note

CIC-DDoS2019 external validation was considered as a best-effort extension. Since the proposed model relies on application-layer and backend-cost features such as route templates, endpoint cost, login behavior, backend timing, status-code ratios, and Nginx partial/timeout signals, the public CIC-DDoS2019 flow-level feature space is not directly compatible with the proposed API-layer feature set.

For this reason, CIC-DDoS2019 was not used as a direct validation source for the proposed model. Instead, a limited external flow-level sanity check was performed on the CIC-DDoS2019 UDPLag subset. The UDPLag training and testing parquet files were combined, binary labels were created as `benign` and `attack`, and a stratified train/test split was applied using CIC flow-level numeric features.

In this limited external sanity check, the flow-level Random Forest achieved:

| Metric | Value |
|---|---:|
| Accuracy | 0.9987 |
| Macro-F1 | 0.9984 |
| Weighted-F1 | 0.9987 |
| Attack recall | 0.9987 |
| Benign FPR | 0.0014 |

The confusion matrix contained 2184 correctly classified benign flows, 3 benign false positives, 5338 correctly classified attack flows, and 7 attack false negatives. These results show that the CIC flow-level features contain strong benign/attack separation signal under a stratified split.

However, this experiment should be interpreted only as a limited external reference check, not as direct external validation of the proposed API-layer detector. The proposed model uses API-specific and backend-specific features that are not available in CIC-DDoS2019. Therefore, full external validation with production API traces or public datasets containing route-level and backend-cost telemetry remains future work.

**Method note.** EWMA and CUSUM baselines were evaluated on the stratified non-chronological test split; therefore, their detection performance should not be interpreted as streaming-time detection performance. They are included as feature-space baselines under the same evaluation protocol as the proposed model.
