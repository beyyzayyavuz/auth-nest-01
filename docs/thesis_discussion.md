# 5. Discussion

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

Overall, the results suggest that behavior-based API-layer DDoS detection can remain effective against mimicry-style attacks in a controlled setting, but further work is needed to test generalization under production traffic, multiple applications, and adaptive adversaries.