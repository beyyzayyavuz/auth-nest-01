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
