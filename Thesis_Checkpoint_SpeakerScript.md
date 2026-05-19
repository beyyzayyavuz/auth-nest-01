# Thesis Checkpoint — Speaker Script (V3 Final)

**Total target time:** ~18–22 minutes
**Tone:** natural, conversational, confident — like explaining to a curious colleague, not reading from notes.
**General tip:** breathe between slides; let the slide register for ~2 seconds before you start talking.

---

## Slide 1 — Title (≈15 sec)

> Good morning. Today I'd like to walk you through where my graduation thesis currently stands.
>
> The project is about behavioral DDoS detection at the API layer — specifically, whether a detection model can still tell attacks apart when the attacker imitates the surface features of a real user.
>
> This is a checkpoint presentation, so I'll cover the full picture, but at a pace where we can discuss anything that catches your eye.

*Tip: smile a little, take a breath, click next.*

---

## Slide 2 — What I Have Completed (≈90 sec)

> Before I dive into the actual story, I want to give a quick summary of what got done since our last conversation. Three buckets.
>
> **First, the infrastructure and traffic side.** I built the full pipeline — NestJS as the application, nginx as the reverse proxy, PostgreSQL for storage. For every single HTTP request I capture per-request backend cost using AsyncLocalStorage — database time, CPU time, query counts isolated cleanly per request. And I run two parallel telemetry streams: nginx access logs at the connection layer, and Prisma RequestLogs at the application layer. On top of that I wrote six k6 traffic scenarios covering legitimate users, HTTP flood, low-rate bot, credential stuffing, mimicry flood, and slowloris.
>
> **Second, features and modeling.** I built a four-tier feature pipeline — 37 features in total across connection, window, global, and baseline-distance layers. I trained a Random Forest classifier as the proposed approach, and a semi-supervised extension stacking an Isolation Forest as an alternative. Crucially, the mimicry scenario was never shown during training — it's strictly a holdout.
>
> **Third, evaluation and writing.** Under production-realistic conditions, the model hits 100% test accuracy in-distribution and 96.38% recall on the mimicry holdout — even though it never saw mimicry during training. Importantly, the ablation study shows that rate-only features alone recall only 73% of mimicry; the behavioral feature pipeline adds 23 percentage points. I also ran a sensitivity analysis across three experimental configurations to make sure the result is robust.
>
> So with that context, let me take you through the whole project, start to finish.

*Tip: this is the "catch-up" slide. Be brisk but clear.*

---

## Slide 3 — The Question in One Sentence (≈60 sec)

> Here's the one sentence the whole thesis is built around.
>
> **If an attacker mimics surface features — User-Agent, IP, even request rate — of a real user, can a behavior-based detector still tell them apart?**
>
> That question breaks down into three sub-questions on the right.
>
> One — are the classical rate-based defenses we all rely on actually enough when the attack is distributed? Two — how discriminative are behavioral features, especially endpoint cost asymmetry? And three — and this is the strict test — can a model that has never seen mimicry during training still flag it as an attack?
>
> The whole rest of the presentation is essentially the experimental answer to these three.

*Tip: pause briefly after reading the main quote. Let it sit.*

---

## Slide 4 — Why is This Question Hard? (≈75 sec)

> Let me ground why this question is harder than it sounds.
>
> **First, traffic is distributed.** Akamai and Cloudflare reports show that a typical Layer 7 attack today spans hundreds to thousands of source IPs. Simple "rate per IP" thresholds are essentially useless.
>
> **Second, attackers mimic surface details.** They rotate User-Agent strings — Chrome, Safari, iPhone. They vary Accept-Language and Accept-Encoding. From the outside, the request looks like a normal browser.
>
> **Third — cost asymmetry.** In my system, calibration shows an /auth/login request costs ~152ms while a /user/profile call costs less than a millisecond — that's roughly 200× difference. Just counting requests misses which endpoints are being hit and at what cost.
>
> **Fourth, the methodological point.** If you train your model on every attack type, of course it does well on a test set with the same attacks. The honest test is whether it catches a variant it has never seen. That's what I designed.

*Tip: lean into point four — this sets up the mimicry-holdout protocol.*

---

## Slide 5 — System Architecture (≈60 sec)

> Here's the system end to end, in one strip.
>
> Traffic generation on the left — k6 plus slowhttptest, running my six scenarios. That hits nginx, which captures connection-level access logs in JSON. From nginx, traffic goes to my NestJS application, where a middleware and an interceptor capture per-request backend cost. Everything lands in PostgreSQL — RequestLog at request level and Connection at connection level. From there, my feature pipeline produces 37 features per window. And finally the model — Random Forest as primary, ISO+RF as alternative.
>
> Two important details. The AsyncLocalStorage pattern isolates per-request metrics cleanly, so database queries belonging to one request never leak into another. And the connection enrichment step — nginx logs HTTP 408 timeouts when slowloris attempts get killed at the edge. I parse those and join them into the Connection table, so slowloris becomes visible to my feature pipeline even though the backend never sees the request.

---

## Slide 6 — Six Traffic Scenarios (≈90 sec)

> Six traffic scenarios. Pay attention to the fifth one — that's the special one.
>
> **S1, legitimate** — synthetic user with Markov navigation, log-normal think times, Zipf search terms. Under V3 conditions, I run 100 concurrent users for production-realistic baseline.
>
> **S2, HTTP flood** — distributed high-rate attack with a naive attacker UA pool.
>
> **S3, low-rate bot** — persistent scraper designed to stay below typical rate thresholds.
>
> **S4, credential stuffing** — random email and password login attempts.
>
> **S5, mimicry flood** — this is the one. UA from the legitimate pool, IPs overlapping legitimate IPs, token reuse, sessions that look like real users. Surface looks legitimate. Behavior is still flood.
>
> **S6, slowloris** — sparse signals because nginx kills slow connections at 60 seconds.
>
> The key design decision at the bottom — **S5 is excluded from training and validation. It only appears in a holdout test partition.** That's how I measure generalization to an unseen attack.

*Tip: slow down on the bottom callout — that's the methodology core.*

---

## Slide 7 — Anatomy of the Mimicry Attack (≈75 sec)

> Let me zoom in on what makes mimicry different from a naive flood.
>
> On the **left**, naive HTTP flood. User-Agent like curl or python-requests — obviously a tool. IP pool attacker-specific with minimal overlap. Every iteration logs in from scratch. Bursty cadence.
>
> On the **right**, mimicry. User-Agents from the legitimate pool — actual Chrome, Safari, iPhone strings. IPs overlap with legitimate traffic. Token reuse, sticky sessions.
>
> So what's left for a detector? The answer at the bottom is the thesis claim: the attacker can imitate the surface, but the endpoint distribution, the backend cost asymmetry, and the session pattern are harder to fake. That's the signal we expect the model to learn.

---

## Slide 8 — Four-Tier Feature Engineering (≈90 sec)

> The feature pipeline has four tiers, 37 features total.
>
> **Tier 1, connection level.** Per-TCP connection: duration, request count, keepalive, partial and timeout flags. This is where the slowloris signal lives, after nginx 408 enrichment.
>
> **Tier 2, window level.** 10-second windows per source IP and /24 subnet. Most discriminative features here: request rate, IAT statistics, endpoint entropy, endpoint cost mean, login presence ratio, 4xx ratio.
>
> **Tier 3, global level.** What's happening system-wide in that 10 seconds — unique IPs, unique subnets, global request rate, new sources. Catches the spread signature of distributed attacks.
>
> **Tier 4, baseline distance.** Markov log-likelihood and IAT KS distance against NASA web trace references.
>
> Together, 37 features, separate rows for IP-level and subnet-level aggregations.

---

## Slide 9 — Proposed Approach (≈75 sec)

> The proposed approach is a **supervised Random Forest** trained on the full 37-feature multi-tier pipeline. The thesis contribution is the feature engineering, not a novel classifier — RF provides a strong baseline that the features can be evaluated against.
>
> On the right, I also tested an **alternative**: a stacked Isolation Forest plus Random Forest model. The Isolation Forest is trained only on normal_user windows, produces an anomaly score, and that score is fed into the RF alongside the original features.
>
> The key finding here — under V3 production-realistic conditions, the ISO+RF extension gives 88.9% mimicry recall, while the supervised RF alone gives 96.4%. The semi-supervised layer becomes redundant when rate signals are well-separated and the supervised model has enough behavioral signal. So I report ISO+RF for completeness but the main model is the Random Forest.

*Tip: the "feature engineering is the contribution, not the model" framing is important — own it.*

---

## Slide 10 — Evaluation Protocol (≈75 sec)

> I evaluate through three independent tests.
>
> **Test A — in-distribution.** Stratified split on the four known classes. Metrics: accuracy, macro-F1, PR-AUC, confusion matrix. Question: does the model separate known attack types correctly?
>
> **Test B — the mimicry holdout.** The strict one. Mimicry is excluded from training entirely. Metrics: recall-as-flood, evasion rate, binary attack recall. Question: can the model catch an attack type it has never seen?
>
> **Test C — leakage and ablation checks.** Random-label permutation sanity (real 99.8% vs permuted 33%, against a class baseline of 25%) plus 12 feature-group ablation experiments. Question: is the model learning real signal or taking shortcuts?
>
> Three independent exams. The whole argument rests on all three pointing the same way.

---

## Slide 11 — Result 1, In-Distribution (≈75 sec)

> Alright, results. In-distribution performance.
>
> Three headline numbers: 100% test accuracy, 100% macro-F1, 100% mean PR-AUC. On the four known attack classes, the model has zero errors across 1446 test windows.
>
> Looking at the per-class table — credential stuffing, http_flood, low_rate_bot, normal_user — every single class is perfect precision and recall.
>
> The reading at the bottom: this is genuine signal, not memorization. The random-label permutation sanity check shows real-label CV accuracy at 99.8% versus permuted-label at 33% — a 67 percentage-point gap that confirms the features carry real information.

*Tip: 100% sounds suspicious to careful audiences — proactively cite the permutation check.*

---

## Slide 12 — Confusion Matrix (≈45 sec)

> The confusion matrix confirms it. All four classes perfect — 396 credential stuffing, 332 http_flood, 145 low_rate_bot, 573 normal_user — every single one on the diagonal.
>
> Zero off-diagonal errors across 1446 windows.
>
> Now the natural skeptical question is — "is this overfitting?" — and the answer is the next test, mimicry holdout, which is harder because the model has never seen the class.

*Tip: the "overfitting" rhetorical question sets up slide 13.*

---

## Slide 13 — ★ Mimicry Holdout (≈120 sec)

> And here we are — the heart of the thesis. The mimicry holdout result.
>
> Just to be crystal clear: this attack type was completely excluded from training. The model never saw a single mimicry window during fitting. It only encountered them during the test phase.
>
> The three numbers — **96.38% of mimicry windows got correctly classified as http_flood.** **3.08% were classified as normal_user — that's the evasion rate.** And **the binary attack recall is 96.92%.**
>
> The chart compares the proposed Random Forest against the ISO+RF alternative. The supervised RF actually outperforms the stacked model here, which is an interesting finding — under realistic legitimate baseline, the unsupervised anomaly layer becomes redundant.
>
> What this result tells me is that the behavioral features I engineered **generalize to an attack variant the model has never been trained on.** The features are not memorizing specific attack signatures — they're capturing something more general about what attacks behaviorally look like.

*Tip: this is THE slide. Slow down, look at the audience, let the numbers land.*

---

## Slide 14 — How to Read the Mimicry Result (≈90 sec)

> Let me unpack what this result means in three layers.
>
> **Layer one — what the attacker did well.** Surface mimicry worked. UA pool, IP overlap, token reuse, sticky sessions — all successfully imitated. Per-window request rate even overlaps normal_user.
>
> **Layer two — what the attacker could not fake.** Endpoint distribution narrow — the attack only bursts on search. Endpoint cost asymmetry doesn't match real users. Login pattern mechanical. Status-code mix tells its own story. These behavioral signatures bleed through.
>
> **Layer three — why this matters.** The model never saw the mimicry variant of these features during training. It still flagged 96.92% of mimicry windows as attack. That's the generalization claim — features carry information that transfers to a *new* attack type.

---

## Slide 15 — ★ Ablation Study (≈90 sec)

> This slide is just as important as the mimicry one, because it answers: **what is the model actually relying on?**
>
> Look at the right column. **All features: 96.4% mimicry recall.** **Rate-only: 73.1% mimicry recall.** The gap is **+23 percentage points** — that's the contribution of behavioral features over rate-only.
>
> **UA-only: 13.2% mimicry recall** — below even the class baseline of 25%. The model does NOT lean on UA as a shortcut.
>
> **Removing global+baseline features: collapses to 14.9% mimicry recall** — a 81 percentage-point drop. Global source diversity is essential for capturing the distributed nature of attacks.
>
> The full model genuinely needs the combination of behavioral signals. This rules out the cheap criticism — "your model just learned to spot tool-like User-Agents" or "your model just learned high rate equals attack." Neither is true.

*Tip: this slide does the heavy lifting in defending the thesis claim. The +23pp number is the key takeaway.*

---

## Slide 16 — Feature Importance (≈60 sec)

> And here are the actual top features, grouped by category.
>
> **Source diversity dominates** — global_unique_ip at #1, global_unique_subnet at #2, global_req_rate at #3. This reflects the distributed nature of the attack scenarios.
>
> **Identity and status** — status_4xx_ratio at #5, login_present_ratio at #7. Auth pattern plus error signal.
>
> **Endpoint cost** — endpoint_cost_mean at #4, endpoint_cost_sum at #10, mean_cpu_time at #8. The backend cost asymmetry I designed.
>
> **Timing behavior** — IAT mean at #9, IAT statistics, IAT KS distance. Strong on mimicry because the ablation showed removing IAT drops mimicry recall by 43 points.
>
> So the model uses a combination of source-diversity, identity, cost, and timing — exactly the multi-signal view I designed.

---

## Slide 17 — Mimicry vs Flood vs Legit Side-by-Side (≈60 sec)

> One more deep-dive comparison. Mimicry vs naive flood vs legit, side by side, across key features.
>
> **req_rate — overlaps.** All three classes share similar rate distributions. Rate alone cannot tell mimicry from legit.
>
> **endpoint_entropy — separates.** Legit around 0.9, mimicry around 0.05. Mimicry only bursts on search.
>
> **endpoint_cost_sum — separates.** Cost asymmetry signal.
>
> **ua_entropy — inverted.** Higher in mimicry than in flood or legit. The attacker actively diversifies UA, and that itself becomes a signal.
>
> This is the granular evidence — behavioral features land on different distributions than legit, even when surface features try to match.

---

## Slide 18 — Latency and FPR (≈75 sec)

> Operational metrics.
>
> **Detection summary table on the left.** Median latency is zero — detection in the first 10-second window. Mimicry binary attack recall 96.92%. In-distribution 100%. Behavioral lift on mimicry +23 percentage points from ablation.
>
> **False positive rate on the right.** Out of all normal-user windows, **zero** false positives. Zero alerts per legitimate IP-minute. This is an improvement over the V1 configuration which had 0.018 — the combination of bug fixes and production-realistic conditions produces a model with no false alarms on legit traffic in this controlled setting.
>
> Operational reading at the bottom — production-acceptable performance with clean signal.

*Tip: FPR=0 is impressive — emphasize it.*

---

## Slide 19 — Calibration Improvement (≈60 sec)

> A transparent note on calibration.
>
> Two charts. On the left, IAT distribution. The KS statistic between my synthetic legitimate traffic and NASA's 1995 trace dropped from 0.994 in the initial configuration to **0.321** in V3. That's substantial alignment — the synthetic distribution now closely tracks NASA in the 0.1 to 10 second range.
>
> On the right, endpoint popularity. Synthetic alpha 2.20 versus NASA 1.25. The shape is preserved — both are Zipf — but the slope is steeper because my API has 4 routes versus NASA's hundreds.
>
> The framing at the bottom: structural properties (log-normal IAT, Zipf endpoint popularity) preserved; numerical parameters re-parameterized per deployment context. NASA is a structural reference, not a target to replicate.

---

## Slide 20 — Scientific Contributions (≈75 sec)

> Three methodological contributions.
>
> **One — Multi-tier behavioral feature pipeline.** 37 features across four tiers. Ablation shows +23 percentage points behavioral lift on mimicry recall over rate-only features. That's the empirical case for the pipeline.
>
> **Two — Mimicry holdout protocol.** Testing on an attack variant explicitly excluded from training is not standard in this literature. I define the protocol explicitly and use it as the central experiment.
>
> **Three — Sensitivity-analyzed reporting.** I identified two implementation issues, corrected them, and re-verified the central finding across three experimental configurations to demonstrate robustness. This level of methodological transparency is unusual for an undergraduate thesis.

*Tip: this slide positions the thesis academically. Speak with conviction.*

---

## Slide 21 — Limitations (≈90 sec)

> The honest list of limitations.
>
> **Scope** — single application. **Data** — synthetic traffic, no production validation. **Adversary** — mimicry is static, not adaptive. **Signal** — slow HTTP is sparse, evaluated by rule. **Auth** — application-layer rate limiting was deliberately disabled to isolate the behavioral signal.
>
> Two important items marked FIXED in green — these are implementation issues I identified, corrected, and re-verified. UserService was using a separate Prisma client bypassing query timing, and the k6 legitimate flow was computing think times without applying sleep. Both fixed in V2 and V3, and the sensitivity analysis in Discussion §5.7 shows the central finding holds across configurations.
>
> External validation is limited — CIC-DDoS2019 sanity check performed but feature space differs.

*Tip: lean into the "FIXED" items. Transparency about identified-and-corrected issues is a strength.*

---

## Slide 22 — Future Work (≈45 sec)

> Five natural extensions.
>
> Multi-application validation. Adaptive adversary. Production trace validation. Protocol-level features like TLS JA3/JA4 fingerprints. Richer slow HTTP telemetry.

---

## Slide 23 — Closing (≈60 sec)

> To wrap up.
>
> The headline verdict: **behavior-based API-layer detection is robust to surface mimicry under production-realistic conditions.** Mimicry holdout 96.38% detection, false positive rate zero, +23 percentage points behavioral lift over rate-only features, UA-only ablation 13% — clear evidence the model does not rely on surface shortcuts.
>
> Three takeaways. **One** — the mimicry holdout protocol is the methodological core; the model generalizes to an unseen attack at 96% recall. **Two** — ablation rules out shortcut learning; behavioral features add 23 points on top of rate. **Three** — implementation issues were identified, corrected, and re-verified across three configurations.
>
> That's the project. I'm happy to discuss any of it — the methodology, the results, the limitations — wherever you'd like to dig in.

*Tip: end on the invitation, not on "any questions?". Stronger close.*

---

## General Speaker Tips

- **Don't memorize this script.** Read it once or twice, internalize the *shape* of each slide. Then deliver in your own words.
- **Numbers you must NOT forget:** 100% in-dist accuracy, 96.38% mimicry recall, 3.08% evasion, 96.92% binary attack recall, FPR = 0, ablation rate-only 73% (behavioral lift +23pp), UA-only 13%, full features 96.4%.
- **If asked something you don't know:** "That's a great question — let me check after the session" is perfectly acceptable.
- **Hostile question about the bugs:** lead with "I identified them, corrected them, and re-verified the central finding across three configurations — see Discussion §5.7" — that reframes from defense to transparency.
- **Hostile question about 100% in-dist accuracy:** "Random-label permutation sanity confirms genuine signal — real-label 99.8% vs permuted 33%, against a class baseline of 25%. The model is learning meaningful features, not memorizing."
- **Hostile question about synthetic traffic:** "Production validation is explicitly listed as future work. V3 configuration brings legit traffic into production-realistic volume — the IAT KS dropped from 0.994 to 0.321, showing substantial alignment with NASA structure."
- **Hostile question about ISO+RF being demoted:** "Sensitivity analysis showed ISO+RF gave marginal benefit under V1 conditions but no benefit under V3. The proposed RF with multi-tier features captures the mimicry signal on its own — that's a finding, not a weakness."

Good luck.
