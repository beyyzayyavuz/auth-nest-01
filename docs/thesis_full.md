# Abstract

Distributed Denial-of-Service (DDoS) attacks against API-based systems are increasingly difficult to detect when attackers avoid simple high-rate patterns and imitate legitimate client behavior. Traditional rate-based defenses may fail when malicious traffic is distributed across multiple sources, uses realistic request rates, or mimics surface-level characteristics such as User-Agent diversity, IP overlap, and session continuity.

This thesis presents a behavior-based API-layer DDoS detection pipeline that combines application-layer request features, endpoint-cost-aware features, backend timing signals, global source diversity, and infrastructure-layer timeout indicators. A controlled experimental environment was implemented using a NestJS API, PostgreSQL, Nginx, k6, and slowhttptest. Six traffic scenarios were generated: legitimate traffic, HTTP flood, low-rate bot, credential stuffing, mimicry flood, and slow HTTP. Features were aggregated over 10-second windows at IP and /24 subnet levels, producing a 37-feature vector across four tiers (connection, window, global, and baseline-distance).

The proposed approach uses a Random Forest classifier trained on the full multi-tier behavioral feature set, evaluated against per-IP rate-threshold, EWMA/CUSUM, and a default Random Forest baseline. A semi-supervised extension stacking an Isolation Forest anomaly score with the Random Forest (ISO+RF) is additionally evaluated as an alternative.

Under production-realistic legitimate traffic conditions, the proposed model achieved 100% in-distribution test accuracy and 100% macro-F1 on the four supervised classes. The main evaluation used a mimicry flood scenario that was excluded from training and used only as a holdout set. The proposed model classified 96.38% of mimicry windows as HTTP flood, with only 3.08% misclassified as normal user traffic and 0.54% as low-rate bot, corresponding to a binary attack recall of 96.92%. The false positive rate on legitimate users was 0 alerts per legitimate IP-minute. Ablation experiments demonstrated that rate-based features alone recall only 73.13% of mimicry windows; the multi-tier behavioral feature pipeline adds 23 percentage points of mimicry recall, demonstrating that behavioral features carry signal complementary to rate, particularly under attacks that adversarially match victim traffic rates. User-Agent-only features performed near random (13.24% mimicry recall), confirming that the model does not rely on surface-level shortcuts.

A sensitivity analysis across three experimental configurations (initial setup, bug-fixed low-volume, and bug-fixed production-realistic) confirms that behavioral feature contribution remains the principal driver of mimicry generalization across conditions. The results suggest that behavior-based API-layer features can provide robust detection against mimicry-style DDoS traffic in a controlled experimental setting. Limitations include synthetic traffic generation, single-application scope, limited external validation, and the absence of fully adaptive adversaries.

# 1. Introduction

## 1.1 Background and Motivation

Modern web applications increasingly rely on API-based architectures. Authentication, user profile access, search functionality, data retrieval, and service-to-service communication are commonly exposed through HTTP APIs. As a result, the availability and reliability of API endpoints have become critical for both users and organizations.

Distributed Denial-of-Service (DDoS) attacks are a major threat to the availability of such systems. Traditional DDoS attacks are often associated with high-volume traffic, where attackers attempt to overwhelm the target by sending a large number of requests or packets. However, not all DDoS attacks are purely volumetric. Some attacks attempt to remain below simple rate thresholds by distributing requests across many sources, lowering the per-source request rate, or targeting expensive endpoints that create high backend cost.

API-layer attacks are especially challenging because different requests can have very different computational effects. For example, a lightweight profile endpoint may require little backend processing, while an authentication endpoint may involve password hashing, database access, and additional validation logic. Therefore, counting requests alone may not fully represent the actual cost imposed on the system.

Another challenge is that attackers can imitate surface-level legitimate behavior. They may rotate User-Agent strings, distribute requests across multiple source identifiers, or use more realistic request intervals. These mimicry-style behaviors make simple signature-based or rate-only detection less reliable. This thesis focuses on whether behavioral features can still distinguish such attack traffic from legitimate traffic.

## 1.2 Problem Statement

Many basic DDoS detection and mitigation approaches rely on volume-based or threshold-based signals, such as request count per IP address, request rate, or sudden traffic spikes. These approaches can detect obvious high-rate attacks, but they may fail when attackers intentionally avoid extreme per-source behavior.

In API systems, this limitation becomes more important because the attacker does not need to generate the highest possible request rate to cause damage. Instead, the attacker may target expensive routes, repeat authentication attempts, or create traffic that appears normal at the surface level while still producing abnormal behavioral patterns.

The central problem addressed in this thesis is the following:

> Can an API-layer DDoS detector still identify malicious traffic when the attacker imitates surface-level legitimate characteristics such as User-Agent diversity and distributed source behavior?

This question is evaluated through a controlled experimental setup that includes both standard attack scenarios and a mimicry flood scenario. The mimicry flood scenario is intentionally excluded from model training and used only as a holdout test. This makes the evaluation stricter because the detector must generalize to an unseen attack variant rather than memorize it during training.

## 1.3 Aim of the Study

The aim of this study is to design, implement, and evaluate a behavior-based API-layer DDoS detection pipeline. The pipeline combines multiple types of signals, including application-layer request behavior, endpoint usage patterns, backend cost indicators, global source diversity, and infrastructure-layer timeout signals.

The study does not aim to build a production-ready DDoS mitigation platform. Instead, it aims to empirically test whether a multi-feature behavioral approach can provide robustness against mimicry-style API attacks in a controlled environment.

The main objectives are:

- to build a controlled API testbed for legitimate and malicious traffic generation,
- to collect application-layer and infrastructure-layer telemetry,
- to extract window-based behavioral features at IP and subnet levels,
- to train and compare baseline models against a proposed stacked model,
- to evaluate model behavior on an unseen mimicry holdout scenario,
- to analyze whether the detector relies on meaningful behavioral signals rather than simple surface features.

## 1.4 Research Question

The main research question of this thesis is:

> To what extent can behavior-based API-layer features detect DDoS traffic when attackers mimic surface-level legitimate behavior?

This question is supported by the following sub-questions:

1. Are simple rate-based baselines sufficient for detecting distributed or mimicry-style API attacks?
2. Do endpoint behavior and endpoint-cost-aware features improve detection performance?
3. Can a model trained without mimicry flood data still identify mimicry traffic as attack-like?
4. Does the model rely primarily on User-Agent features, or does it learn broader behavioral patterns?
5. Can infrastructure-layer timeout signals improve visibility into slow HTTP attacks that do not reach backend middleware?

## 1.5 Scope of the Study

The study is conducted in a controlled laboratory environment. A NestJS API, PostgreSQL database, and Nginx reverse proxy are used to build the experimental system. Traffic is generated using k6 and slowhttptest. The scenarios include legitimate traffic, HTTP flood, low-rate bot behavior, credential stuffing, mimicry flood, and slow HTTP behavior.

The focus is on API-layer and application-aware detection. Therefore, the feature set includes route templates, endpoint entropy, endpoint cost, status-code ratios, backend timing, login-related behavior, global source diversity, and Nginx timeout-derived connection signals.

The study does not include full production deployment, TLS fingerprinting, browser fingerprinting, HTTP/2-specific attacks, or a fully adaptive adversary that iteratively optimizes against the trained detector. These are treated as future work.

## 1.6 Contributions

This thesis makes the following contributions:

1. **Controlled API-layer DDoS testbed:**  
   A controlled experimental environment is implemented using NestJS, PostgreSQL, Nginx, Docker, k6, and slowhttptest. This environment supports multiple legitimate and malicious traffic scenarios.

2. **Multi-tier behavioral feature pipeline:**  
   The study extracts features from application-layer request logs, connection-level summaries, global window statistics, session-level behavior, and baseline-distance measurements.

3. **Nginx timeout enrichment for slow HTTP visibility:**  
   Slow HTTP attacks may be terminated by Nginx before they reach backend middleware. This study integrates Nginx 408 timeout records into the connection feature pipeline to capture partial and timeout-based slow HTTP signals.

4. **Mimicry holdout evaluation protocol:**  
   The mimicry flood scenario is excluded from training and validation and used only as a holdout test set. This evaluates generalization to an unseen attack variant that imitates surface-level legitimate behavior.

5. **Stacked anomaly-supervised detection model:**  
   The proposed model combines an Isolation Forest trained only on normal-user traffic with a Random Forest classifier trained on the full feature set plus an anomaly score.

6. **Ablation and leakage sanity checks:**  
   Feature ablation experiments and random-label permutation tests are used to evaluate whether the model depends on meaningful behavioral features rather than accidental leakage or narrow surface-level shortcuts.

## 1.7 Thesis Organization

The remainder of the thesis is organized as follows.

Chapter 2 reviews related work on DDoS detection, application-layer attacks, behavioral anomaly detection, and mimicry-style evasion. Chapter 3 presents the methodology, including the experimental system, traffic scenarios, feature engineering pipeline, dataset preparation, models, and evaluation design. Chapter 4 reports the experimental results, including detection performance, mimicry holdout evaluation, ablation analysis, detection latency, and false positive rate. Chapter 5 discusses the implications of the results, methodological contributions, limitations, and future work. Chapter 6 concludes the thesis.
# 3. Methodology

This chapter describes the experimental system, traffic generation process, feature extraction pipeline, dataset construction strategy, and detection models used in this study. The methodology is designed to evaluate whether behavior-based API-layer DDoS detection can remain effective when attackers imitate surface-level legitimate client characteristics such as User-Agent diversity and distributed source behavior.

The proposed pipeline consists of four main stages. First, a controlled API environment was implemented using a NestJS backend, PostgreSQL database, and Nginx reverse proxy. Second, multiple legitimate and malicious traffic scenarios were generated using k6 and slowhttptest. Third, raw request and connection logs were transformed into window-based behavioral features at different aggregation levels. Finally, baseline models and the proposed stacked anomaly-supervised model were trained and evaluated using in-distribution test data and a mimicry holdout set.

A key design choice in this methodology is that the mimicry flood scenario was excluded from training and validation. It was used only as a holdout test set. This allows the evaluation to measure whether the model generalizes to an attacker that attempts to imitate legitimate traffic characteristics rather than merely memorizing the mimicry scenario during training.

---

## 3.1 System Overview

The experimental environment was built as a controlled API-layer DDoS detection testbed. The backend application was implemented with NestJS and exposed through an Nginx reverse proxy. PostgreSQL was used as the storage layer for request logs, connection-level records, scenario metadata, endpoint cost profiles, and window labels.

The system was designed to capture both application-layer and infrastructure-layer signals. Application-layer request information was collected through backend middleware and stored in the `RequestLog` table. This included request timestamp, source IP, route template, HTTP method, response status, response time, database query count, database timing, CPU timing, login-related indicators, User-Agent information, and scenario labels.

Some slow HTTP attacks do not reach the NestJS middleware because they are terminated at the Nginx layer before a full backend request is completed. For this reason, Nginx access logs were also parsed to capture HTTP 408 timeout events. These timeout records were used to enrich the `Connection` table with `partialRequestCount` and `timeoutRequestCount`, allowing slowloris-style behavior to be represented in the feature set even when the backend middleware did not observe the incomplete requests.

The overall system therefore combines three types of signals:

- application-layer request behavior,
- backend cost and processing behavior,
- infrastructure-layer timeout and partial-connection behavior.

---

## 3.2 Data Collection Architecture

The data collection pipeline is based on three main database tables: `RequestLog`, `Connection`, and `WindowLabel`.

The `RequestLog` table stores per-request application-layer observations. Each request contains timing information, endpoint information, HTTP status code, source information, and traffic labels. This table is the primary source for request-rate, inter-arrival-time, endpoint, status-code, and backend-cost features.

The `Connection` table stores connection-level summaries. It is generated by aggregating requests by connection identifier and enriched with Nginx timeout records. This step is especially important for slow HTTP attacks, because slowloris and slow POST connections may be closed by Nginx before they reach the backend middleware. In such cases, the connection-level Nginx enrichment allows timeout-based signals to be preserved.

The `WindowLabel` table stores window-level labels used during supervised learning and evaluation. Features are aggregated into fixed 10-second windows at different aggregation levels, such as per-IP and per-/24 subnet. Each window is assigned a majority label based on the traffic observed in that window.

---

## 3.3 Traffic Scenario Design

Six main traffic scenarios were designed to represent legitimate use and different attack behaviors.

### S1 — Legitimate traffic

The legitimate traffic scenario represents normal API usage. It includes authentication and user-related routes such as login, logout, profile access, and search behavior. This scenario provides the baseline for normal application-layer behavior.

### S2 — HTTP flood

The HTTP flood scenario represents a high-volume request attack. Instead of relying only on a single extremely high-rate source, the attack is modeled as distributed traffic across multiple sources. This makes the scenario more realistic against simple per-IP rate-limiting assumptions.

### S3 — Low-rate bot

The low-rate bot scenario represents a stealthier attack pattern. It produces lower request rates per source and is designed to be closer to normal traffic than a naive flood. This scenario tests whether behavioral features can detect attacks that do not rely on obvious volume spikes.

### S4 — Credential stuffing

The credential stuffing scenario focuses on repeated authentication attempts. It is designed to stress login-related endpoints and backend authentication cost. This scenario is important because authentication endpoints can have much higher computational cost than lightweight read endpoints.

### S5 — Mimicry flood

The mimicry flood scenario is the main holdout scenario in this study. It imitates surface-level legitimate characteristics such as User-Agent diversity and distributed source behavior. This scenario was excluded from training and validation and used only as a holdout test set. Its purpose is to evaluate whether the model can detect attack behavior when the attacker attempts to look more legitimate at the surface level.

### S6 — Slow HTTP / slowloris

The slow HTTP scenario represents low-and-slow connection exhaustion behavior. In this scenario, some attack connections are terminated by Nginx before they reach the backend application. Therefore, Nginx 408 timeout logs were used to enrich the connection-level features. Since the final slow HTTP signal appeared in a small number of timeout-heavy windows, this class was evaluated separately rather than treated as a standard supervised multiclass training class.

---

## 3.4 Feature Engineering

The feature extraction process was organized into multiple tiers.

### Tier 1 — Connection-level features

Tier 1 features summarize behavior at the connection level. These include connection duration, request count per connection, keep-alive usage, mean and maximum request time, partial request count, and timeout request count. Nginx 408 timeout events were parsed and mapped into this layer to capture slow HTTP behavior that did not reach the backend middleware.

### Tier 2 — Window-level behavioral features

Tier 2 features are computed over fixed 10-second windows for each source IP and /24 subnet. These include:

- request count,
- request rate,
- inter-arrival-time statistics,
- endpoint uniqueness,
- endpoint entropy,
- endpoint cost sum and mean,
- User-Agent uniqueness and entropy,
- mean response time,
- backend database and CPU timing,
- status-code ratios,
- login presence ratio,
- partial and timeout ratios.

This tier represents the main behavior-based detection layer.

### Tier 3 — Global window features

Tier 3 features summarize system-wide behavior within each 10-second window. These include the number of unique IPs, the number of unique /24 subnets, total request count, global request rate, and new-source ratio. These features help capture distributed attack behavior that may not appear as extreme when each source is considered individually.

### Tier 4 — Session-level features

Tier 4 features summarize session-level behavior when session identifiers are available. These include session request count, session duration, number of unique endpoints per session, mean response time, login count, endpoints per request, and requests per second. These features provide an additional view of authenticated or semi-authenticated behavior.

### Baseline-distance features

Additional derived features were computed by comparing API traffic behavior against NASA-derived baseline references. These include Markov log-likelihood over endpoint categories and IAT KS distance. These features were not used to claim exact reproduction of NASA traffic. Instead, they provide reference-distance signals that capture how far a window deviates from a historical web-traffic-inspired baseline.

---

## 3.5 Calibration Reference

NASA web server traces were used as a calibration reference during the design of legitimate traffic generation and baseline-distance features. However, the final synthetic legitimate API traffic was not treated as an exact replay of NASA traffic. The experimental system is an API-specific environment with a small number of routes, while the NASA trace represents a large historical web server workload.

A later distributional comparison showed that the synthetic legitimate traffic shows substantial alignment with NASA in the V3 configuration. The IAT KS distance is 0.321, with the synthetic distribution closely tracking NASA in the 0.1–10 second range. Endpoint popularity shows a Zipf-like decreasing trend; the synthetic API has a steeper slope (α ≈ 2.20 vs NASA α ≈ 1.25) due to the smaller endpoint set. Therefore, NASA traces are described in this study as structural calibration references rather than exact validation targets — the shape (log-normal IAT, Zipf endpoint popularity) is preserved, while numerical parameters are reparameterized per deployment context.

---

## 3.6 Dataset Preparation and Labeling

The final dataset was built from `master_features.parquet`, which combines Tier 2, Tier 3, and baseline-distance features. S6 retry artifacts such as broken or slow-only intermediate runs were removed from the final supervised dataset. Recovery windows were normalized as `normal_user`.

The class labels were normalized into the following categories:

- `normal_user`,
- `http_flood`,
- `low_rate_bot`,
- `credential_stuffing`,
- `mimicry_flood`,
- `slow_http`.

The `mimicry_flood` class was separated as a holdout test-only set and was not included in training, validation, or standard test splits. The `slow_http` class contained too few window-level rows for reliable supervised multiclass training, so it was also separated into a dedicated `slow_http_test` split and evaluated using connection-level partial and timeout signals.

The remaining in-distribution classes were split into stratified train, validation, and test sets:

- `normal_user`,
- `http_flood`,
- `low_rate_bot`,
- `credential_stuffing`.

A stratified split was used because a pure time-based split caused some classes to disappear from validation and test sets due to the sequential execution of scenarios.

To reduce data leakage risk, metadata and label-proxy columns were removed before training. The dropped columns included `scenario_id`, `majority_label`, `label`, `split`, `window_start`, `window_end`, and `aggregation_key`. The `aggregation_type` column was retained as a categorical indicator and one-hot encoded.

---

## 3.7 Baseline Models

Three baseline models were implemented.

### Baseline 1 — Per-IP request-rate threshold

The first baseline uses only the `req_rate` feature. The threshold was selected as the 95th percentile of `req_rate` among normal-user training windows. Windows above this threshold were classified as attacks, and the rest were classified as normal. This baseline represents a simple rate-limiting style detector.

### Baseline 2 — EWMA + CUSUM

The second baseline uses statistical change detection on per-window request rate. Normal-user training data was used to calibrate the mean and standard deviation of request rate. EWMA and CUSUM were then used to detect upward deviations from normal request-rate behavior. This baseline represents a simple online anomaly detection method based on rate changes.

### Baseline 3 — Random Forest

The third baseline is a supervised multiclass Random Forest trained on the full in-distribution feature set. It predicts one of the four in-distribution classes: `normal_user`, `http_flood`, `low_rate_bot`, and `credential_stuffing`. The mimicry class is not included in training and is evaluated separately as holdout traffic.

---

## 3.8 Proposed Approach

The proposed approach is a supervised Random Forest classifier trained on the full multi-tier behavioral feature pipeline (37 features across the four tiers described in §3.4). The classifier uses 200 trees with the `balanced_subsample` class-weight strategy to handle class-size differences across the four supervised classes.

The key methodological choices are:

1. **Multi-tier feature combination.** The model receives behavioral features from all four tiers simultaneously (connection-level, 10-second window, global, baseline-distance). The ablation study in §4.4 demonstrates that this combination is necessary; no single feature group alone is sufficient for mimicry generalization.

2. **Mimicry holdout protocol.** The `mimicry_flood` class is excluded from training and validation; the model only encounters mimicry during the holdout test. This evaluates whether the model generalizes to a previously unseen attack variant.

3. **Semi-supervised alternative (ISO+RF).** A stacked extension was additionally evaluated, in which an Isolation Forest trained only on `normal_user` windows produces an `anomaly_score` feature, which is then added to the supervised Random Forest input. The Isolation Forest decision function is inverted so that higher `anomaly_score` values indicate more anomalous behavior. This alternative is evaluated and reported alongside the main model; under the V3 configuration it provides no additional discriminative power on the mimicry holdout (see §4.3 and Discussion §5.7).

The proposed Random Forest is evaluated against three baselines (per-IP rate threshold, EWMA/CUSUM, and a default-configured Random Forest with no class weighting) and the ISO+RF alternative.

---

## 3.9 Evaluation Design

The evaluation uses both in-distribution and holdout settings.

In-distribution performance is measured on the standard test split using accuracy, macro-F1, weighted-F1, per-class precision, recall, and PR-AUC. Macro-F1 is emphasized because aggregate accuracy can be misleading when class distributions are imbalanced.

The mimicry holdout set is evaluated separately. Since `mimicry_flood` is not included as a training class, the model cannot directly predict this label. Therefore, mimicry evaluation uses three metrics:

- `mimicry_recall_as_flood`: the fraction of mimicry windows predicted as `http_flood`,
- `mimicry_evasion_rate`: the fraction of mimicry windows predicted as `normal_user`,
- `mimicry_binary_attack_recall`: the fraction of mimicry windows predicted as any non-normal class.

False positive behavior is measured as false positives per legitimate IP-minute. Detection latency is computed post-hoc using scenario-flow ordering. For each attack scenario, the first detected attack window is compared against the scenario start time.

Ablation analysis is used to evaluate the contribution of feature groups. Feature groups such as IAT features, endpoint features, connection features, global/baseline-distance features, cost features, status features, UA-only features, and rate-only features are removed or isolated to test whether the model depends on a narrow shortcut signal. The UA-only ablation is especially important for testing whether the classifier relies mainly on User-Agent surface features.

Random-label permutation testing is used as an additional leakage sanity check. The model is evaluated with real labels and randomly permuted labels. A large performance gap between real-label and permuted-label performance indicates that the feature set carries meaningful signal rather than relying on accidental leakage.
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

# 5. Discussion

This chapter interprets the results of the experimental evaluation and discusses their implications for behavior-based API-layer DDoS detection. The main finding is that the proposed feature pipeline remains effective against mimicry-style attacks in the controlled experimental environment, and that this effectiveness is driven primarily by behavioral feature groups rather than rate-based shortcuts. In particular, the mimicry flood scenario was excluded from training and used only as a holdout set, yet the proposed Random Forest model classified 96.38% of mimicry windows as `http_flood`, with only 3.08% misclassified as `normal_user`.

---

## 5.1 Behavioral Discrimination Beyond Surface Features

The central question of this thesis is whether behavior-based DDoS detection remains useful when an attacker imitates surface-level legitimate characteristics. The mimicry flood scenario was designed to test this question by introducing realistic client diversity (User-Agent strings drawn from the legitimate pool, IP overlap with the legitimate pool, token-reuse session patterns) while still operating at flood-level total request rates.

The results show that the proposed Random Forest classified 96.38% of mimicry windows as `http_flood`, with binary attack recall of 96.92% and an evasion rate of only 3.08%. Since the mimicry class was not included in training, this result indicates that the model did not memorize the mimicry scenario; it learned behavioral patterns that generalized to a previously unseen attack variant.

The ablation study provides the strongest evidence for this interpretation. The `rate_only` configuration recalls 73.13% of mimicry windows; the full feature set recalls 96.38%. The 23 percentage-point gap is attributable to behavioral features that cannot be inferred from request volume alone — endpoint distribution, endpoint cost, login pattern, status-code mix, inter-arrival-time irregularities, and source diversity at the global window level.

The `ua_only` configuration recalls only 13.24% of mimicry windows, well below the four-class baseline of 25%. If the classifier had depended primarily on User-Agent features, the UA-only ablation would have performed substantially better. Instead, the full model required a broader behavioral feature set. The mimicry deep-dive analysis confirms that mimicry traffic shows higher User-Agent entropy than both naive flood and legitimate traffic, but this surface diversity is not what the model uses; it is the endpoint and cost asymmetry that the attacker cannot fake.

---

## 5.2 Endpoint-Cost-Aware Feature Contribution

One of the important design choices in this study is the inclusion of endpoint-cost-aware features. In many API systems, different endpoints impose very different backend costs. In the experimental system, the calibration on legitimate traffic produced the following per-endpoint mean total cost: `/auth/login` 152 ms (driven by bcrypt password hashing), `/auth/logout` 4.86 ms, `/user/search` 3.42 ms (LIKE query with insensitive matching), and `/user/profile` 0.73 ms. This represents a ~200× cost asymmetry across routes, captured directly in the `endpoint_cost_mean` and `endpoint_cost_sum` features.

The feature importance analysis shows that endpoint-related and cost-related features (`endpoint_cost_mean` at #4, `endpoint_cost_sum` at #10, `login_present_ratio` at #7, `mean_cpu_time` at #8) consistently appear in the top-importance group. Together with the global source diversity features (`global_unique_ip`, `global_unique_subnet`, `global_req_rate`, `global_request_count`) that dominate the top-importance ranking under production-realistic conditions, the model gains a multi-signal view: it knows not only how many requests are made and from how many sources, but also which endpoints are targeted, what they cost on the backend, and whether the requests come from authenticated sessions.

The ablation study confirms the necessity of this multi-signal view. Rate-only detection achieves 92.81% in-distribution validation accuracy but falls to 73.13% mimicry recall — the rate-only configuration cannot distinguish mimicry from flood because mimicry deliberately matches flood rates. The full feature set raises mimicry recall to 96.38%, with the 23 percentage-point lift coming from behavioral signals invisible to rate-only views.

---

## 5.3 Slow HTTP Detection Through Nginx Timeout Enrichment

The slow HTTP scenario revealed an important data collection issue. Slowloris and slow POST connections may be terminated at the Nginx layer before they reach the backend application. As a result, these events may not appear in application middleware logs such as `RequestLog`.

Initially, the slow HTTP feature outputs showed zero values for `partialRequestCount`, `timeoutRequestCount`, `partial_ratio`, and `timeout_ratio`, even though Nginx logs contained many HTTP 408 timeout entries. This happened because the incomplete slow HTTP requests were closed by Nginx before NestJS middleware could observe them.

To address this, the connection feature pipeline was enriched with Nginx 408 timeout logs. These logs were parsed and mapped into the `Connection` table, allowing slow HTTP behavior to appear as partial and timeout connection features. After this enrichment, the S6 slowloris scenario produced non-zero partial and timeout connection counts (200 enriched connections in the V3 run).

This finding has two implications. First, API-layer DDoS detection should not rely only on backend middleware logs, because some attacks are stopped earlier at the reverse proxy. Second, infrastructure-layer signals such as timeout events can provide useful detection features when integrated into the application-layer feature pipeline.

The slow HTTP signal was sparse in the final scenario because Nginx closed slow connections around the timeout threshold. Therefore, slow HTTP was not treated as a normal supervised multiclass class. Instead, it was evaluated separately using connection-level partial and timeout signals. This is a realistic outcome for production-like reverse proxy behavior and should be interpreted as a limitation of the supervised window-level dataset rather than a failure of the logging pipeline.

---

## 5.4 Calibration Reference and Synthetic Traffic Validity

NASA web server traces were used as a calibration reference during the design of legitimate traffic generation and baseline-distance features. Under the V3 configuration, with log-normal think times applied and 100 concurrent legitimate users, the IAT distribution shows substantial alignment with NASA: the KS statistic dropped from 0.994 (V1 configuration) to 0.321 (V3), with the synthetic distribution closely tracking NASA in the 0.1–10 second range.

The endpoint popularity comparison showed a Zipf-like decreasing pattern in both NASA and synthetic traffic, but the synthetic traffic has a steeper slope (α ≈ 2.20 vs NASA α ≈ 1.25). This is expected because the experimental API has a much smaller endpoint set (4 active routes) than the NASA trace (hundreds of paths).

For these reasons, NASA is best understood as a structural reference rather than an exact validation target. The synthetic traffic generation process is informed by real web traffic structure (log-normal IAT shape, Zipf endpoint popularity), but numerical parameters (μ_log, α) are reparameterized per deployment context. The final evaluation is based primarily on controlled in-system scenarios, mimicry holdout testing, ablation analysis, and leakage checks.

---

## 5.5 Methodological Contributions

This study makes several methodological contributions.

**First**, it introduces a mimicry holdout evaluation protocol for API-layer DDoS detection. The mimicry attack is not included in training or validation and is used only as a holdout test set. This makes the evaluation stricter than testing only on attack variants already seen during training.

**Second**, the study combines application-layer, backend-cost, global-window, and infrastructure-layer features into a single 37-feature pipeline organized across four tiers. The feature set includes request-rate statistics, inter-arrival-time statistics, endpoint entropy, endpoint cost (derived from real backend timing telemetry), backend timing, status ratios, global source diversity, and Nginx timeout-derived connection signals.

**Third**, the study uses random-label permutation testing as a leakage sanity check. The large performance gap between real-label (99.8% CV accuracy) and permuted-label (33.0% CV accuracy) evaluation, against a four-class baseline of 25%, indicates that the model is learning meaningful signal rather than relying on accidental label leakage.

**Fourth**, the ablation study explicitly checks whether the model depends on narrow shortcuts such as User-Agent features or request rate alone. The very poor UA-only result (13.24% mimicry recall) and the substantial gap between rate-only and full-feature mimicry recall (73.13% vs 96.38%) support the interpretation that the model depends on a broader behavioral feature set.

**Fifth**, the study reports a sensitivity analysis across three experimental configurations (Discussion §5.7), demonstrating that the central finding — behavioral features add meaningful discriminative power on mimicry holdout — holds across implementation conditions.

---

## 5.6 Limitations

Several limitations should be acknowledged.

**Implementation issues identified and corrected.** Two implementation issues were identified during the project and corrected before the final reported results. (i) `UserService` initially used a separate `PrismaClient` instance, bypassing the global query interceptor and under-measuring search endpoint backend cost. This was corrected by injecting the shared `PrismaService` via the module system. (ii) The k6 legitimate flow computed log-normal think times via the `THINK` helper but did not pass the values to `sleep()`, resulting in per-VU request rates higher than realistic legitimate user activity. This was corrected by wrapping all `THINK.*()` calls in `sleep()`. The final reported results (V3 configuration) use the corrected pipeline. Sensitivity analysis comparing the original (V1) and intermediate bug-fixed (V2) configurations is provided in §5.7.

**Controlled experimental environment.** The evaluation is based on a controlled synthetic experimental environment. Although the scenarios are designed to reflect realistic attack behaviors and the V3 configuration produces production-realistic legitimate traffic volume, this is not a substitute for large-scale production traffic.

**Single application scope.** The system is evaluated on a single API application. The feature set includes application-specific concepts such as route templates and endpoint cost profiles. Therefore, the results may not directly generalize to other applications without recalibration.

**Limited external validation.** Full external validation on a public dataset such as CIC-DDoS2019 was not used as a primary evaluation source. A limited CIC-DDoS2019 UDPLag flow-level sanity check was performed and showed strong benign/attack separation under a stratified split. However, this does not constitute direct external validation of the proposed API-layer detector because CIC-DDoS2019 does not provide route templates, endpoint cost, backend timing, login behavior, or Nginx timeout-derived features. Therefore, external validation on application-layer production traces remains necessary.

**Non-adaptive adversary.** The mimicry flood scenario imitates surface-level legitimate characteristics, but it does not iteratively adapt to the trained model. A stronger adversary could potentially optimize endpoint choices, timing, request cost, and User-Agent behavior after observing detector feedback.

**Application-layer auth defenses disabled.** Application-layer rate limiting and account lockout logic in `AuthService` were deliberately disabled during traffic generation. This was done to isolate the behavioral detection layer's signal from auth-side mitigations. In production deployment, both layers would coexist; auth-side checks would handle credential stuffing while behavioral detection would identify distributed attacks that bypass per-account thresholds.

**Sparse slow HTTP signal.** The slow HTTP evaluation is limited by the behavior of Nginx timeout handling. The slow HTTP signal appeared as a sparse set of timeout-heavy windows rather than a sustained supervised class. This makes slow HTTP detection better suited to rule-based or connection-level evaluation in this experiment.

**Excluded protocol-level features.** The experiment does not include TLS fingerprinting, HTTP/2-specific attack vectors, or browser-level fingerprint features. These could provide additional detection or evasion signals in production environments.

---

## 5.7 Sensitivity Analysis Across Experimental Configurations

To assess the robustness of the main result, the full pipeline was evaluated under three configurations:

**V1 (original setup):** the initial experimental configuration. Contained the two implementation issues described in §5.6. Under V1, the proposed ISO+RF model achieves 99.14% in-distribution accuracy and 91.96% mimicry recall (5.74% evasion). Rate-only ablation recall is 71%.

**V2 (bug-fixed, low legitimate volume):** both implementation issues corrected, but legitimate traffic remained at the original VU count, producing low total RPS relative to attack scenarios. Mimicry recall rises to 99.43%; however, the ablation rate-only result climbs to 88%, indicating that the model leans heavily on rate features when the legit-attack rate gap is wide.

**V3 (bug-fixed, production-realistic legitimate volume):** legitimate traffic scaled to 100 concurrent users with applied log-normal think times. Total legitimate RPS becomes comparable in order of magnitude to attack scenarios. Under V3, the supervised Random Forest achieves 100% in-distribution accuracy and 96.38% mimicry recall (3.08% evasion). The ISO+RF stacking extension produces 88.91% mimicry recall, indicating that under V3 the unsupervised anomaly layer becomes redundant; the supervised RF with multi-tier features captures the mimicry signal on its own.

**Cross-configuration interpretation.** All three configurations produce mimicry recall ≥ 91.96%, and in all three the ablation studies show that behavioral features add substantial discriminative power beyond rate. Under V3 specifically — which is the closest to production conditions — the ablation gap between rate-only (73.13%) and full feature set (96.38%) is the largest in absolute mimicry recall terms (+23 percentage points), providing the strongest evidence for the central claim. The convergence of these results across V1, V2, and V3 supports the thesis claim that behavior-based API-layer detection is robust to surface mimicry under controlled experimental conditions.

The V3 configuration is therefore used as the primary reported result throughout this thesis. Appendix A provides the full per-configuration metric tables and ablation results.

---

## 5.8 Future Work

Future work should extend this study in several directions.

**First**, the proposed method should be evaluated on multiple API applications with different endpoint structures and cost profiles. This would test whether the feature engineering approach generalizes beyond a single application.

**Second**, future experiments should include iterative adaptive adversaries. Such attackers could observe detection feedback and modify endpoint selection, timing, source distribution, and header behavior to reduce detection probability.

**Third**, external validation should be explored with datasets that contain application-layer features or with production API traces where route templates and backend cost signals are available. Public network-flow datasets can still be useful, but they are not fully aligned with the feature space used in this study.

**Fourth**, additional protocol-level features could be included, such as TLS JA3/JA4 fingerprints, HTTP/2 behavior, browser automation signals, and client-side timing patterns.

**Fifth**, slow HTTP detection could be expanded by collecting richer reverse-proxy and socket-level telemetry. This would allow slowloris-style attacks to be modeled more continuously rather than as sparse timeout windows.

Overall, the results suggest that behavior-based API-layer DDoS detection can remain effective against mimicry-style attacks in a controlled setting, but further work is needed to test generalization under production traffic, multiple applications, and adaptive adversaries.

# 6. Conclusion

This thesis investigated whether behavior-based API-layer DDoS detection can remain effective when attackers imitate surface-level legitimate traffic characteristics. The study focused on a controlled API environment where legitimate traffic, HTTP flood, low-rate bot, credential stuffing, mimicry flood, and slow HTTP scenarios were generated and analyzed.

The main contribution of the study is a behavior-based detection pipeline that combines application-layer request features, endpoint-cost-aware features, backend timing features, global window features, and infrastructure-layer timeout signals into a single 37-feature multi-tier vector. The proposed approach uses a Random Forest classifier trained on this feature set; a semi-supervised extension stacking an Isolation Forest anomaly score (ISO+RF) is reported as an alternative.

The experimental results show that the proposed Random Forest model achieved 100% in-distribution test accuracy and 100% macro-F1 on the four supervised classes (1446 test windows with zero misclassifications). More importantly, the mimicry flood scenario was excluded from training and evaluated only as a holdout set. The proposed model classified 96.38% of mimicry windows as `http_flood`, with only 3.08% misclassified as `normal_user` and 0.54% as `low_rate_bot`. The binary attack recall on the mimicry holdout was 96.92%, and the false positive rate on legitimate user traffic was 0 alerts per legitimate IP-minute. These results indicate that the detector did not rely solely on surface-level characteristics such as User-Agent diversity, but instead used broader behavioral signals that generalize to a previously unseen attack variant.

The ablation study provides the strongest evidence for this interpretation. Rate-based features alone recall only 73.13% of mimicry windows, while the full multi-tier behavioral feature pipeline recalls 96.38% — a contribution of 23 percentage points from behavioral signals that cannot be inferred from request volume alone. User-Agent-only features perform near random (13.24% mimicry recall), confirming that the model does not use surface-level features as shortcuts. Removing the inter-arrival-time feature group drops mimicry recall by 43 percentage points, and removing the global+baseline-distance feature group drops mimicry recall by 81 percentage points, demonstrating that mimicry robustness arises from the combination of multiple behavioral feature groups rather than from any single feature category.

The study also showed that slow HTTP behavior requires infrastructure-layer visibility. Nginx 408 timeout enrichment was necessary to capture partial and timeout connection signals that did not reach the backend middleware. This highlights the importance of combining reverse-proxy telemetry with application-layer logs in API-layer DDoS detection.

A sensitivity analysis across three experimental configurations (initial setup with implementation issues, bug-fixed with original legitimate volume, and bug-fixed with production-realistic legitimate volume) confirms that the central finding holds across implementation conditions. Across all three configurations, mimicry recall remains above 91% and ablation studies consistently show that behavioral features add discriminative power beyond rate-based detection.

Overall, the results suggest that behavior-based API-layer DDoS detection can provide robustness against mimicry-style attacks in a controlled setting. However, the study is limited to a single application and synthetic laboratory traffic. Future work should evaluate the approach on multiple applications, production traces, richer external datasets, and adaptive adversaries that iteratively optimize their behavior against the detector.
