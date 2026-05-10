# Abstract

Distributed Denial-of-Service (DDoS) attacks against API-based systems are increasingly difficult to detect when attackers avoid simple high-rate patterns and imitate legitimate client behavior. Traditional rate-based defenses may fail when malicious traffic is distributed across multiple sources, uses realistic request rates, or mimics surface-level characteristics such as User-Agent diversity.

This thesis presents a behavior-based API-layer DDoS detection pipeline that combines application-layer request features, endpoint-cost-aware features, backend timing signals, global source diversity, and infrastructure-layer timeout indicators. A controlled experimental environment was implemented using a NestJS API, PostgreSQL, Nginx, k6, and slowhttptest. Six traffic scenarios were generated: legitimate traffic, HTTP flood, low-rate bot, credential stuffing, mimicry flood, and slow HTTP. Features were aggregated over 10-second windows at IP and subnet levels.

The proposed model uses a stacked anomaly-supervised approach. First, an Isolation Forest is trained only on normal-user traffic to generate an anomaly score. Then, a Random Forest classifier is trained using the full behavioral feature set plus this anomaly score. The model is evaluated against rate-threshold, EWMA/CUSUM, and Random Forest baselines.

The proposed model achieved 0.9914 test accuracy and 0.9923 macro-F1 on the in-distribution test set. The main evaluation used a mimicry flood scenario that was excluded from training and used only as a holdout set. The proposed model classified 92.41% of mimicry windows as HTTP flood and only 5.61% as normal user traffic, corresponding to approximately 94.39% binary attack recall. Ablation results showed that User-Agent-only features performed poorly, indicating that the model did not rely on surface-level shortcuts.

The results suggest that behavior-based API-layer features can improve robustness against mimicry-style DDoS traffic in a controlled setting. Limitations include synthetic traffic generation, single-application scope, limited external validation, and the absence of fully adaptive adversaries.# 1. Introduction

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

Chapter 2 reviews related work on DDoS detection, application-layer attacks, behavioral anomaly detection, and mimicry-style evasion. Chapter 3 presents the methodology, including the experimental system, traffic scenarios, feature engineering pipeline, dataset preparation, models, and evaluation design. Chapter 4 reports the experimental results, including detection performance, mimicry holdout evaluation, ablation analysis, detection latency, and false positive rate. Chapter 5 discusses the implications of the results, methodological contributions, limitations, and future work. Chapter 6 concludes the thesis.# 3. Methodology

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

A later distributional comparison showed that the synthetic legitimate traffic did not exactly match the NASA IAT distribution. The IAT KS distance was high, indicating a substantial mismatch. Endpoint popularity showed a Zipf-like decreasing trend, but the synthetic API had a steeper slope due to the smaller endpoint set. Therefore, NASA traces are described in this study as calibration references rather than exact validation targets.

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

## 3.8 Proposed Model

The proposed model is a stacked anomaly-supervised approach consisting of two layers.

### Layer A — Isolation Forest

The first layer is an Isolation Forest trained only on `normal_user` training windows. This model produces an anomaly score for every window. Since the Isolation Forest decision function assigns higher scores to more normal samples, the score was inverted so that higher `anomaly_score` values indicate more anomalous behavior.

### Layer B — Random Forest with anomaly score

The second layer is a Random Forest classifier trained on the original feature set plus the Isolation Forest anomaly score. This allows the supervised model to use both behavior-specific features and a general normality-deviation signal.

The proposed model is evaluated against the Random Forest baseline to determine whether the anomaly score provides additional benefit, especially on the mimicry holdout set.

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

Random-label permutation testing is used as an additional leakage sanity check. The model is evaluated with real labels and randomly permuted labels. A large performance gap between real-label and permuted-label performance indicates that the feature set carries meaningful signal rather than relying on accidental leakage.# 4. Results

This chapter presents the experimental results of the proposed API-layer DDoS detection pipeline. The evaluation focuses on six main aspects: calibration reference comparison, in-distribution detection performance, mimicry holdout behavior, feature ablation, detection latency, and false positive rate. The main objective is to determine whether behavior-based features can detect DDoS traffic even when the attacker attempts to imitate surface-level legitimate characteristics.

---

## 4.1 Calibration Reference Comparison

NASA web server traces were used as a calibration reference during the design of the legitimate traffic generator and baseline-distance features. The purpose of this comparison was not to exactly replay NASA traffic, but to evaluate how the final synthetic API traffic relates to a historical real-world web traffic reference.

Figure 7 compares the inter-arrival time (IAT) distribution of the synthetic legitimate traffic with the NASA Jul 1995 trace. The resulting KS statistic was high (`KS = 0.9945`), indicating that the final synthetic API traffic did not closely match the NASA IAT distribution. This result is expected to some extent because the experimental environment is an API-specific system with authentication and user routes, while NASA represents a broader historical web server workload. Therefore, NASA is treated as a calibration reference rather than an exact validation target.

[fig7_iat_calibration]

Figure 8 compares endpoint popularity using a Zipf-style rank-frequency plot. Both NASA and synthetic legitimate traffic show a decreasing rank-frequency trend. However, the synthetic API traffic has a steeper slope because the experimental API contains a much smaller and more constrained endpoint set. The synthetic endpoint popularity alpha was approximately `1.71`, while the NASA reference alpha was approximately `1.25`.

[fig8_zipf_calibration]

Overall, the calibration comparison shows that the generated legitimate traffic follows some structural assumptions such as non-uniform endpoint popularity, but it does not exactly reproduce the full distributional characteristics of NASA traffic. This is treated as a limitation and discussed further in Chapter 5.

---

## 4.2 Detection Performance

The first main evaluation compares the baseline Random Forest model with the proposed Isolation Forest + Random Forest model. The proposed model adds an anomaly score generated by an Isolation Forest trained only on normal-user traffic.

Table 1 summarizes the overall in-distribution test performance.

**Table 1. Overall test performance.**

| Model | Accuracy | Macro-F1 | Weighted-F1 |
|---|---:|---:|---:|
| Baseline RF | 0.9907 | 0.9918 | 0.9907 |
| Proposed ISO+RF | 0.9914 | 0.9923 | 0.9914 |

The proposed model slightly improved all overall metrics compared with the baseline RF. The improvement is small because the baseline RF already performs very strongly on the in-distribution test set. However, the direction of improvement is consistent across accuracy, macro-F1, and weighted-F1.

Table 2 shows the per-class metrics for the proposed model.

**Table 2. Per-class metrics for the proposed ISO+RF model.**

| Class | Precision | Recall | F1-score | Support |
|---|---:|---:|---:|---:|
| credential_stuffing | 1.0000 | 1.0000 | 1.0000 | 378 |
| http_flood | 0.9899 | 0.9879 | 0.9889 | 495 |
| low_rate_bot | 0.9870 | 1.0000 | 0.9935 | 76 |
| normal_user | 0.9868 | 0.9868 | 0.9868 | 454 |

The model performs strongly across all four in-distribution classes. Credential stuffing and low-rate bot traffic were classified with near-perfect performance. The main remaining errors occurred between `http_flood` and `normal_user`, which is expected because distributed flood behavior can overlap with legitimate per-source request patterns.

Figure 1 shows the confusion matrix of the proposed model on the in-distribution test set.

[fig1_confusion_matrix]

The confusion matrix confirms that the majority of errors occur between `http_flood` and `normal_user`. The model correctly classified all `credential_stuffing` windows and all `low_rate_bot` windows in the test set.

Table 3 reports the per-class PR-AUC values.

**Table 3. Per-class PR-AUC.**

| Class | Baseline RF | Proposed ISO+RF |
|---|---:|---:|
| credential_stuffing | 1.0000 | 1.0000 |
| http_flood | 0.9995 | 0.9995 |
| low_rate_bot | 1.0000 | 1.0000 |
| normal_user | 0.9993 | 0.9993 |

The PR-AUC values are very high for all classes, showing that the proposed model separates the in-distribution classes well. Figure 3 visualizes the same PR-AUC comparison.

[fig3_pr_auc]

---

## 4.3 Mimicry Holdout Evaluation

The mimicry holdout evaluation is the key experiment in this study. The `mimicry_flood` scenario was excluded from training and validation. It was used only as a holdout test set. This design tests whether the model can detect attack behavior when the attacker attempts to imitate surface-level legitimate characteristics.

Since `mimicry_flood` is not a training class, the model cannot directly predict that label. Therefore, three metrics were used:

- `mimicry_recall_as_flood`: fraction of mimicry windows predicted as `http_flood`,
- `mimicry_evasion_rate`: fraction of mimicry windows predicted as `normal_user`,
- `mimicry_binary_attack_recall`: fraction of mimicry windows predicted as any non-normal class.

Table 4 shows the mimicry holdout prediction distribution.

**Table 4. Mimicry holdout prediction distribution.**

| Predicted class | Baseline RF | Proposed ISO+RF |
|---|---:|---:|
| http_flood | 0.9152 | 0.9241 |
| normal_user | 0.0638 | 0.0561 |
| low_rate_bot | 0.0210 | 0.0198 |

The proposed model classified `92.41%` of mimicry windows as `http_flood`. Only `5.61%` of mimicry windows were classified as `normal_user`. Therefore, the proposed model achieved an approximate binary attack recall of `94.39%` on the mimicry holdout set.

Figure 2 visualizes the mimicry prediction distribution.

[fig2_mimicry_holdout]

The result indicates that mimicry traffic was usually mapped to an attack-like class rather than being accepted as legitimate traffic. This supports the central claim that behavior-based features can remain effective even when surface-level characteristics are made more realistic.

Figure 10 provides a focused breakdown of the proposed model’s mimicry classifications.

[fig10_mimicry_breakdown]

The mimicry deep-dive analysis also compares mimicry traffic with naive flood and legitimate traffic across key features. Figure 9 shows that mimicry traffic can resemble legitimate traffic in some surface or rate-related dimensions, but it differs strongly in endpoint-level behavioral features such as endpoint entropy and endpoint cost.

[fig9_mimicry_features]

In particular, mimicry traffic showed higher User-Agent entropy, which is consistent with an attacker attempting to create surface-level diversity. However, the UA-only ablation performed poorly, indicating that the classifier did not rely primarily on User-Agent features. Instead, the model used a broader set of behavioral and endpoint-level signals.

---

## 4.4 Ablation Study

The ablation study evaluates how different feature groups contribute to detection performance. Feature groups were removed or isolated, and the model was retrained under each condition.

Figure 6 summarizes the ablation results.

[fig6_ablation]

The full feature set achieved the strongest and most balanced performance. The `ua_only` setting performed very poorly, with validation accuracy around `0.0949`. This result is important because it shows that the model is not simply using User-Agent features as a shortcut.

The `rate_only` setting achieved moderate in-distribution performance but performed much worse on the mimicry holdout set. This confirms that request rate alone is insufficient for detecting mimicry-style attacks. This result is also consistent with the weak performance of the rate-threshold and EWMA/CUSUM baselines.

Endpoint-only features were strong for binary mimicry attack detection, but they did not fully reproduce the balanced behavior of the full model. Global and baseline-distance features performed well in-distribution but showed poor mimicry generalization when used alone. These results suggest that mimicry robustness depends on combining multiple behavioral feature groups rather than relying on a single feature category.

Figure 4 shows the top feature importances of the proposed ISO+RF model.

[fig4_feature_importance]

The most important features included endpoint entropy, login presence ratio, endpoint cost mean, status 4xx ratio, global unique subnet count, endpoint uniqueness, Markov log-likelihood, database timing, CPU timing, endpoint cost sum, and anomaly score. The presence of `anomaly_score` among the top features indicates that the Isolation Forest layer contributed additional information, although the improvement over the already-strong baseline RF was modest.

---

## 4.5 Detection Latency and False Positive Rate

Detection latency was computed using scenario-flow ordering. For each attack scenario, the first detected attack window was compared with the scenario start time.

Table 5 summarizes the scenario-level latency results.

**Table 5. Detection latency by scenario.**

| Scenario | Expected label | Detected | Latency (sec) | Scenario recall |
|---|---|---:|---:|---:|
| S2_http_flood | http_flood | True | 0 | 0.8696 |
| S3_low_rate_bot | low_rate_bot | True | 10 | 0.4663 |
| S4_credential_stuffing | credential_stuffing | True | 0 | 0.8201 |
| S5_mimicry_flood | mimicry_flood | True | 0 | 0.8960 |
| S6_slowloris | slow_http | True | 0 | 0.0020 |

The median detection latency was `0.0` seconds, and the p95 latency was approximately `8.0` seconds. The slowest detection was observed for the low-rate bot scenario, which was detected after 10 seconds. This is expected because low-rate attacks are designed to be closer to normal behavior.

The slow HTTP scenario was detected immediately when timeout/partial-connection signals appeared, but its scenario-level recall was low because the slow HTTP signal was sparse in the 30-minute window. This is consistent with the Nginx behavior observed during the experiment, where slow HTTP connections were closed around the timeout threshold.

False positive behavior was measured on normal-user IP-level windows. The proposed model produced 8 false positive windows out of 2642 normal-user IP-level windows. This corresponds to:

- window-level FPR: `0.003028`,
- legitimate IP-minutes: `440.33`,
- FPR per legitimate IP-minute: `0.018168`.

This suggests that the proposed model produces a low false positive rate under the controlled experimental setting.

---

## 4.6 External Validation Note

CIC-DDoS2019 external validation was considered as a best-effort extension. However, the proposed feature set is highly application-layer specific. It includes route templates, endpoint cost, login behavior, backend timing, status-code ratios, and Nginx partial/timeout signals. Public flow-level datasets such as CIC-DDoS2019 generally provide packet-flow and network-level features rather than application-specific API and backend-cost features.

For this reason, CIC-DDoS2019 was not used as a primary validation source in this study. The primary evaluation instead relies on controlled in-system scenarios, mimicry holdout testing, random-label permutation checks, ablation analysis, false positive measurement, and detection latency analysis. The lack of full external validation is treated as a limitation and discussed in Chapter 5.# 5. Discussion

This chapter interprets the results of the experimental evaluation and discusses their implications for behavior-based API-layer DDoS detection. The main finding is that the proposed feature set remains effective against mimicry-style attacks in the controlled experimental environment. In particular, the mimicry flood scenario was excluded from training and used only as a holdout set, yet the proposed model classified most mimicry windows as attack-like rather than legitimate.

---

## 5.1 Behavioral Discrimination Beyond Surface Features

The central question of this thesis is whether behavior-based DDoS detection remains useful when an attacker imitates surface-level legitimate characteristics. The mimicry flood scenario was designed to test this question by introducing more realistic client diversity and avoiding obvious single-source rate spikes.

The results show that the proposed ISO+RF model classified 92.41% of mimicry windows as `http_flood`, while only 5.61% were classified as `normal_user`. This corresponds to an approximate binary attack recall of 94.39% on the mimicry holdout set. Since the mimicry class was not included in training, this result suggests that the model did not simply memorize the mimicry scenario. Instead, it learned behavioral patterns that generalized to a previously unseen attack variant.

The ablation study further supports this interpretation. The UA-only model performed very poorly, with validation accuracy around 0.0949. This indicates that the classifier was not relying primarily on User-Agent diversity as a shortcut. This point is important because mimicry traffic showed higher User-Agent entropy than both naive flood and legitimate traffic. If the classifier had depended mainly on User-Agent-related features, the UA-only ablation would have performed much better. Instead, the full model required a broader behavioral feature set.

The mimicry deep-dive analysis also showed that mimicry traffic can resemble legitimate traffic in some rate or surface dimensions, but it differs strongly in endpoint-level behavior. In particular, endpoint entropy and endpoint cost features helped distinguish mimicry traffic from legitimate user behavior. This supports the thesis claim that behavior-based features provide additional robustness beyond surface attributes such as User-Agent strings.

---

## 5.2 Endpoint-Cost-Aware Feature Contribution

One of the important design choices in this study is the inclusion of endpoint-cost-aware features. In many API systems, different endpoints impose very different backend costs. For example, an authentication endpoint that performs password hashing is significantly more expensive than a lightweight profile read endpoint. A detection system that only counts requests may fail to capture this asymmetry.

The feature importance analysis showed that endpoint-related and cost-related features were among the most important features for the proposed model. These included `endpoint_entropy`, `endpoint_cost_mean`, `endpoint_cost_sum`, `login_present_ratio`, `mean_db_time`, and `mean_cpu_time`. This suggests that the model benefited from understanding not only how many requests were made, but also which endpoints were targeted and how expensive those requests were.

The ablation study also showed that rate-only detection is insufficient. The `rate_only` model achieved moderate in-distribution performance but performed poorly on mimicry holdout traffic. This aligns with the poor results of the rate-threshold and EWMA/CUSUM baselines. In contrast, the full feature set achieved strong in-distribution performance and strong mimicry holdout performance. This indicates that endpoint behavior, cost asymmetry, timing, status-code ratios, and global source diversity jointly contribute to detection robustness.

The results therefore support the use of endpoint-cost-aware behavioral features in API-layer DDoS detection, especially for attacks that attempt to remain below obvious per-source rate thresholds.

---

## 5.3 Slow HTTP Detection Through Nginx Timeout Enrichment

The slow HTTP scenario revealed an important data collection issue. Slowloris and slow POST connections may be terminated at the Nginx layer before they reach the backend application. As a result, these events may not appear in application middleware logs such as `RequestLog`.

Initially, the slow HTTP feature outputs showed zero values for `partialRequestCount`, `timeoutRequestCount`, `partial_ratio`, and `timeout_ratio`, even though Nginx logs contained many HTTP 408 timeout entries. This happened because the incomplete slow HTTP requests were closed by Nginx before NestJS middleware could observe them.

To address this, the connection feature pipeline was enriched with Nginx 408 timeout logs. These logs were parsed and mapped into the `Connection` table, allowing slow HTTP behavior to appear as partial and timeout connection features. After this enrichment, the S6 slowloris scenario produced non-zero partial and timeout connection counts.

This finding has two implications. First, API-layer DDoS detection should not rely only on backend middleware logs, because some attacks are stopped earlier at the reverse proxy. Second, infrastructure-layer signals such as timeout events can provide useful detection features when integrated into the application-layer feature pipeline.

The slow HTTP signal was sparse in the final scenario because Nginx closed slow connections around the timeout threshold. Therefore, slow HTTP was not treated as a normal supervised multiclass class. Instead, it was evaluated separately using connection-level partial and timeout signals. This is a realistic outcome for production-like reverse proxy behavior and should be interpreted as a limitation of the supervised window-level dataset rather than a failure of the logging pipeline.

---

## 5.4 Calibration Reference and Synthetic Traffic Validity

NASA web server traces were used as a calibration reference during the design of legitimate traffic generation and baseline-distance features. However, the distributional comparison showed that the final synthetic API traffic does not exactly match the NASA IAT distribution. The IAT KS distance was high, indicating substantial mismatch.

This result should be interpreted carefully. The NASA trace represents a historical public web server workload with many paths and long-tailed access patterns. The experimental system in this thesis is a controlled API environment with a small number of routes and structured authentication/user flows. Therefore, exact distributional similarity is not expected.

The endpoint popularity comparison showed a Zipf-like decreasing pattern in both NASA and synthetic traffic, but the synthetic traffic had a steeper slope. This is also expected because the experimental API has a smaller and more constrained endpoint set than the NASA trace.

For these reasons, NASA is best understood as a calibration reference rather than an exact validation target. The synthetic traffic generation process was informed by real web traffic structure, but the final evaluation is based primarily on controlled in-system scenarios, mimicry holdout testing, ablation analysis, and leakage checks.

---

## 5.5 Methodological Contributions

This study makes several methodological contributions.

First, it introduces a mimicry holdout evaluation protocol for API-layer DDoS detection. The mimicry attack is not included in training or validation and is used only as a holdout test set. This makes the evaluation stricter than testing only on attack variants already seen during training.

Second, the study combines application-layer, backend-cost, global-window, and infrastructure-layer features. The feature set includes request-rate statistics, inter-arrival-time statistics, endpoint entropy, endpoint cost, backend timing, status ratios, global source diversity, and Nginx timeout-derived connection signals.

Third, the study uses random-label permutation testing as a leakage sanity check. The large performance gap between real-label and permuted-label evaluation indicates that the model is learning meaningful signal rather than relying on accidental label leakage.

Fourth, the ablation study explicitly checks whether the model depends on narrow shortcuts such as User-Agent features or request rate alone. The poor UA-only and rate-only results support the interpretation that the model depends on a broader behavioral feature set.

---

## 5.6 Limitations

Several limitations should be acknowledged.

First, the evaluation is based on a controlled synthetic experimental environment. Although the scenarios are designed to reflect realistic attack behaviors, they are not a substitute for large-scale production traffic.

Second, the system is evaluated on a single API application. The feature set includes application-specific concepts such as route templates and endpoint cost profiles. Therefore, the results may not directly generalize to other applications without recalibration.

Third, full external validation on a public dataset such as CIC-DDoS2019 was not used as a primary evaluation source. Public flow-based datasets do not directly provide many of the application-layer and backend-cost features used in this study, such as route templates, endpoint cost, login behavior, backend timing, and Nginx timeout enrichment.

Fourth, the adversary is not fully adaptive. The mimicry flood scenario imitates surface-level legitimate characteristics, but it does not iteratively adapt to the trained model. A stronger adversary could potentially optimize endpoint choices, timing, request cost, and User-Agent behavior after observing detector feedback.

Fifth, the slow HTTP evaluation is limited by the behavior of Nginx timeout handling. The slow HTTP signal appeared as a sparse set of timeout-heavy windows rather than a sustained supervised class. This makes slow HTTP detection better suited to rule-based or connection-level evaluation in this experiment.

Finally, the experiment does not include TLS fingerprinting, HTTP/2-specific attack vectors, or browser-level fingerprint features. These could provide additional detection or evasion signals in production environments.

---

## 5.7 Future Work

Future work should extend this study in several directions.

First, the proposed method should be evaluated on multiple API applications with different endpoint structures and cost profiles. This would test whether the feature engineering approach generalizes beyond a single application.

Second, future experiments should include iterative adaptive adversaries. Such attackers could observe detection feedback and modify endpoint selection, timing, source distribution, and header behavior to reduce detection probability.

Third, external validation should be explored with datasets that contain application-layer features or with production API traces where route templates and backend cost signals are available. Public network-flow datasets can still be useful, but they are not fully aligned with the feature space used in this study.

Fourth, additional protocol-level features could be included, such as TLS JA3/JA4 fingerprints, HTTP/2 behavior, browser automation signals, and client-side timing patterns.

Fifth, slow HTTP detection could be expanded by collecting richer reverse-proxy and socket-level telemetry. This would allow slowloris-style attacks to be modeled more continuously rather than as sparse timeout windows.

Overall, the results suggest that behavior-based API-layer DDoS detection can remain effective against mimicry-style attacks in a controlled setting, but further work is needed to test generalization under production traffic, multiple applications, and adaptive adversaries.# 6. Conclusion

This thesis investigated whether behavior-based API-layer DDoS detection can remain effective when attackers imitate surface-level legitimate traffic characteristics. The study focused on a controlled API environment where legitimate traffic, HTTP flood, low-rate bot, credential stuffing, mimicry flood, and slow HTTP scenarios were generated and analyzed.

The main contribution of the study is a behavior-based detection pipeline that combines application-layer request features, endpoint-cost-aware features, backend timing features, global window features, and infrastructure-layer timeout signals. The proposed model uses a stacked approach in which an Isolation Forest trained only on normal-user traffic produces an anomaly score, and a Random Forest classifier uses this score together with the full behavioral feature set.

The experimental results show that the proposed ISO+RF model achieved strong in-distribution performance, with a test accuracy of 0.9914 and macro-F1 of 0.9923. More importantly, the mimicry flood scenario was excluded from training and evaluated only as a holdout set. The proposed model classified 92.41% of mimicry windows as `http_flood`, while only 5.61% were classified as `normal_user`. This indicates that the detector did not rely only on surface-level characteristics such as User-Agent diversity, but instead used broader behavioral signals.

The ablation study further supports this conclusion. The UA-only configuration performed poorly, while the full feature set achieved the most balanced performance. This suggests that endpoint entropy, endpoint cost, status-code behavior, timing statistics, global source diversity, and anomaly-score features collectively contributed to mimicry robustness.

The study also showed that slow HTTP behavior requires infrastructure-layer visibility. Nginx 408 timeout enrichment was necessary to capture partial and timeout connection signals that did not reach the backend middleware. This highlights the importance of combining reverse-proxy telemetry with application-layer logs in API-layer DDoS detection.

Overall, the results suggest that behavior-based API-layer DDoS detection can provide robustness against mimicry-style attacks in a controlled setting. However, the study is limited to a single application and synthetic laboratory traffic. Future work should evaluate the approach on multiple applications, production traces, richer external datasets, and adaptive adversaries that iteratively optimize their behavior against the detector.