# Demo Walkthrough Map — VS Code Live Tour

**For:** Final pre-defense meeting with thesis advisor.
**Format:** Open VS Code, walk through the project chronologically, end with the result.
**Goal:** Show that you understand *every* decision — not just *what* you built, but *why* each piece exists and *what evidence* each piece produced.

---

## 0. Where to start — and why

You have four candidates: k6 first, real datasets first, database first, architecture first. **Don't start with any of them.** Start with **the research question**, then **architecture**, then go in build-order.

Reasoning:
- **Architecture-first alone** feels like a tool tour. The advisor sees boxes, not story.
- **k6-first** skips the *why* — you'd be explaining tools before motivation.
- **Datasets-first** front-loads calibration before the advisor knows what's being calibrated.
- **Database-first** is too far down the stack to be the opener.

Best flow: **WHY → WHAT → HOW IT'S BUILT → HOW IT'S MEASURED → WHAT IT FOUND**. This is the natural shape of a research narrative — and matches the actual chronological order in which you built the project.

---

## 1. The high-level map (story arc)

| # | Stage | Time | What you prove here |
|---|---|---|---|
| 1 | The research question | 1–2 min | "Mimicry attacks are the unsolved part; I built a way to test against them." |
| 2 | System architecture | 1–2 min | "Single data path, end-to-end controlled." |
| 3 | The SUT (NestJS app + DB) | 2 min | "I measure backend cost per request, not just rate." |
| 4 | Traffic generation (k6) | 3–4 min | "Six scenarios, S5 is held out — never seen during training." |
| 5 | Real-trace calibration | 2–3 min | "Distribution shape (lognormal, Zipf, Markov) is borrowed from NASA/ClarkNet; values are context-fit." |
| 6 | Data ingestion path | 1–2 min | "nginx + Prisma + Connection enrichment — slowloris becomes visible." |
| 7 | Feature engineering (4 tiers) | 3–4 min | "37 features across four scopes — connection, window, global, baseline distance." |
| 8 | Model + evaluation | 3–4 min | "RF + four independent checks: in-distribution, 5-fold CV, mimicry holdout, ablation." |
| 9 | Results, limits, contribution | 2 min | "96.4% mimicry recall, +23pp behavioral lift, two bugs found and re-verified across V1/V2/V3." |

**Total full version: ~20–22 min.** Trim to 10 min by collapsing stages 5, 6 and shortening 7.

---

## 2. VS Code tab order (pre-flight, BEFORE the meeting)

Open these 14 tabs in this exact order. Use `⌘+P`, type the filename, repeat.

| # | File | Why this tab exists |
|---|---|---|
| 1 | `docs/thesis_methodology.md` | Backup anchor if you lose the thread. §3.1 has the research question. |
| 2 | `docker-compose.yml` | Architecture in one glance — shows nginx + postgres + slowhttptest. |
| 3 | `src/middleware/request-logger.middleware.ts` | The per-request cost capture (AsyncLocalStorage). Core data-collection logic. |
| 4 | `src/user/user.service.ts` | The Prisma bug-fix (V2). Bring this up *only* if asked about robustness. |
| 5 | `prisma/schema.prisma` | Data models: `RequestLog`, `Connection`, `EndpointCostProfile`, `CalibrationBaseline`. |
| 6 | `k6/common/legitimate-user-flow.js` | Markov navigation + log-normal think — the legitimate-user behavior model. |
| 7 | `k6/scenarios/01_legitimate_only.js` | The S1 baseline that all other scenarios layer on top of. |
| 8 | `k6/scenarios/05_mimicry_flood.js` | **The star.** The holdout-only mimicry scenario. |
| 9 | `infra/nginx/nginx.conf` | JSON access log format + 60s timeout (why slowloris is visible). |
| 10 | `analysis/scripts/12_tier2_features.py` | The 10-second window aggregator. The most important analysis script. |
| 11 | `analysis/scripts/15_baseline_distance.py` | Markov log-likelihood + IAT KS — the "distance from NASA" feature. |
| 12 | `analysis/scripts/26_mimicry_holdout_analysis.py` | The holdout evaluation script — produces the 96.38% number. |
| 13 | `analysis/scripts/28_cross_validation.py` | The 5-fold CV (newest addition). |
| 14 | `docs/attack_calibration_sources.md` | Citation-verified parameter sources. Open this if asked "why these numbers?" |

Also have **one terminal** open at the project root.

**Do NOT open:** `node_modules/`, `analysis/venv/`, `k6/_legacy/`, `k6/scenarios/07_mix_slow.js`, `k6/scenarios/08_mix_all.js` (orphan), `dist/`, `backups/`. If they appear, close them — they create noise.

---

## 3. Speaking scripts — stage by stage

Tone: confident student. Short sentences. Use the file names and function names casually — it shows you wrote it.

---

### Stage 1 — The research question (1–2 min)

**Open:** No file yet. Just the VS Code window with the project open. Optionally `docs/thesis_methodology.md` on screen.

**Say:**

> "Hocam, my thesis question is one sentence. If an attacker mimics the surface of a real user — User-Agent, IP, even request rate — can a behavior-based detector still tell them apart from a legitimate user?
>
> The reason this matters is that classical defenses fail here. Per-IP rate limiting fails because attacks are distributed. UA filtering fails because attackers rotate User-Agent strings. So I wanted to test whether *behavioral* features — endpoint cost asymmetry, source diversity, timing patterns — survive surface mimicry.
>
> The whole project is a controlled experiment to answer that. I built a target API, I generated six attack scenarios, I excluded one of them from training, and I checked whether the model still catches it. Let me walk you through the pieces."

**Connection to next:** "First, here's the architecture — one shot, then we'll go through each piece."

---

### Stage 2 — System architecture (1–2 min)

**Open:** `docker-compose.yml`. Scroll so all three services (`postgres`, `nginx`, `slowhttptest`) are visible.

**Say:**

> "The architecture is deliberately simple, because the experiment depends on the data path being controlled and repeatable. Three containers — `nginx` as the reverse proxy, `postgres` as the data store, `slowhttptest` for the slow-HTTP attack container. The NestJS application runs on the host, behind nginx.
>
> Traffic generation runs from outside — k6 sends HTTP requests through nginx, into NestJS, which writes to Postgres. So everything I generate ends up in tables I control. No external collection, no missing data."

**Point to:** the three service definitions.

**Connection:** "Now let me show you the application side — specifically, how I capture per-request cost, because rate alone wasn't enough."

---

### Stage 3 — The SUT: NestJS application & data capture (2 min)

**Open:** `src/middleware/request-logger.middleware.ts`. Scroll to the top.

**Say:**

> "This middleware runs on every HTTP request. Two things matter here. First, I assign a `correlationId` and start measuring `process.hrtime` and `process.cpuUsage` immediately. Second, I create a per-request `metrics` object — `dbQueryCount`, `dbTotalTimeMs`, `cpuTimeMs`. This object is isolated per-request through AsyncLocalStorage, in `src/common/request-context/request-context.ts`.
>
> Why this matters: rate alone can't distinguish a /user/profile call from a /auth/login call, but bcrypt makes login ~200× more expensive than profile. If I only count requests, I miss the asymmetry. So this middleware writes the cost per request to the `RequestLog` table."

**Switch tab to:** `prisma/schema.prisma`. Scroll to `model RequestLog`.

**Say:**

> "This is the schema. `RequestLog` stores the cost per request — `responseTimeMs`, `dbTotalTimeMs`, `cpuTimeMs`, the endpoint, the status, the source IP. `Connection` stores per-TCP-connection metadata — when slowloris keeps a connection half-open for 60 seconds, this table captures it. `EndpointCostProfile` is the calibration table — once I knew the cost of each route, I cached it here for the feature pipeline."

**(Skip unless asked:)** Tab `src/user/user.service.ts` — only mention if the advisor asks about robustness or bugs. Then say:

> "By the way, this file is where the V2 bug fix lives. I originally instantiated PrismaClient locally inside UserService, which bypassed my query timing capture. I refactored it to use the injected PrismaService — now every query runs through the instrumented client. Fixed, re-ran the whole pipeline, the central result still holds."

**Connection:** "OK, the application side is logging everything. Now let me show you the traffic side — the six scenarios."

---

### Stage 4 — Traffic generation: k6 + slowhttptest (3–4 min)

**Open:** `k6/scenarios/01_legitimate_only.js`. Scroll to the imports and the `options` block.

**Say:**

> "This is the legitimate user scenario — S1. It imports `runLegitSession` from a shared common file. Let me open that."

**Switch tab to:** `k6/common/legitimate-user-flow.js`. Scroll to the Markov transition matrix or whatever has the navigation graph.

**Say:**

> "Inside this file is the legitimate-user behavior model. Three pieces. First, a Markov navigation graph — login → search → profile → search → logout. The transition probabilities come from cross-trace analysis of NASA, ClarkNet, and Calgary access logs — we'll get to that. Second, log-normal think times — sampled with the `lognormalSample` helper, parameters re-fit for a modern API context. Third, Zipf search-term sampling — heavy-tail like real user query distributions.
>
> One important detail: there's a V2 bug fix in here. I had been computing log-normal think times but never passing them to `sleep()`. Fixed — now per-VU rates are realistic, around 0.3 req/s per VU."

**Switch tab to:** `k6/scenarios/05_mimicry_flood.js`. Scroll to the `options` block and the IP/UA pool selection.

**Say:**

> "Now the centerpiece. S5 mimicry holdout. This scenario is *test-only* — the model never sees it during training. The design has four ingredients."
>
> "First, the UA pool — `SOPHISTICATED_ATTACKER_AGENTS` is the legit UA pool, not the naive bot pool. So the model can't use UA as a shortcut."
>
> "Second, the IP pool — `getIpPool('sophisticated')` returns IPs that *overlap* with the legitimate pool. So the model can't use IP reputation as a shortcut either."
>
> "Third, token reuse — `if (s.iterationCount >= 50)` re-logs in only every 50 iterations. Normal floods re-login every request. So this looks like a sticky session, like a real user."
>
> "Fourth, the rate — same `stages` envelope as `02_http_flood.js`, peak 200 req/s. This is deliberate: I keep the rate the *same* as the naive flood so I'm only varying the behavioral surface. If I changed the rate too, I couldn't tell whether the model is catching mimicry or just rate."

**Switch tab to:** `infra/nginx/nginx.conf`. Scroll to the `log_format` block and the timeout settings.

**Say:**

> "Nginx does two things for me. One — the JSON access log captures per-request metadata that doesn't reach the application, especially when nginx returns a 408 timeout. That's how slowloris becomes visible — slowloris connections never complete, so they never reach the application, but nginx logs them with status 408. Two — the 60-second `client_body_timeout` is what kills slowloris on the proxy side, which is exactly the constraint a real reverse proxy would impose."

**Connection:** "All this traffic looks structurally realistic because I calibrated it against real public traces. Let me show you that step."

---

### Stage 5 — Real-trace calibration (2–3 min)

**Open terminal** in project root. Run:

```bash
ls analysis/data/raw/
```

**Say:**

> "I downloaded five real web traces — NASA Jul95, NASA Aug95, ClarkNet Aug28, ClarkNet Sep4, and Calgary. These are public 1995-era access logs from the Internet Traffic Archive, widely used in web measurement research.
>
> I extracted three distribution families from these: log-normal inter-arrival times, Zipf endpoint popularity, and Markov navigation transitions. The point wasn't to *replicate* NASA — my API has 4 routes, NASA has hundreds — it was to *borrow the shape* of legitimate behavior."

**Switch tab to:** `analysis/scripts/15_baseline_distance.py`. Scroll to the function that computes `markov_log_likelihood` or `iat_ks_distance`.

**Say:**

> "This is where I turn the calibration into a feature. For every 10-second window, I compute `markov_log_likelihood` — how likely the observed navigation sequence is under the NASA-derived transition matrix. And `iat_ks_distance` — the Kolmogorov–Smirnov distance between the window's inter-arrival times and the NASA log-normal fit. So 'distance from a legitimate baseline' becomes two numerical features in the model."
>
> "Important honesty point: I excluded Calgary from session-aware analysis. The Calgary trace is anonymized to two virtual hosts, so I can't reconstruct user sessions from it. I kept it for endpoint Zipf only. This is documented in the cross-trace report."

**Connection:** "Now everything lands in the database. Let me show you how the data path actually flows."

---

### Stage 6 — Data ingestion path (1–2 min)

**Switch tab to:** `prisma/schema.prisma`. Scroll through the models quickly.

**Say:**

> "Three independent telemetry streams come together. First, the NestJS middleware writes `RequestLog` rows with cost-per-request. Second, nginx writes JSON access logs, which an ingestion script joins onto the `Connection` table — this is where the 408 timeout signal becomes a row. Third, after each scenario the orchestration script writes a `Scenario` row with start and end times, so I can align traffic to labels.
>
> Then everything gets exported to parquet — `analysis/data/features/` — and from there the Python pipeline takes over. I don't read from Postgres during analysis. The export is a deliberate boundary: postgres is for collection, parquet is for analysis."

**Connection:** "Once the data is on disk, the feature pipeline runs. This is the part I want to show you in detail."

---

### Stage 7 — Feature engineering (3–4 min) — **THE LINGER**

**Open:** `analysis/scripts/12_tier2_features.py`. This is the most important analysis script. Scroll to the window aggregation loop.

**Say:**

> "Tier 2 is the heart of the pipeline. It takes per-request rows and aggregates them into 10-second windows, grouped by source IP and by /24 subnet. For each window, it computes about a dozen features."

**Point to:** the line where `endpoint_entropy`, `iat_cv`, `endpoint_cost_mean` are computed.

**Say:**

> "Some of these are simple — `req_rate`, `status_4xx_ratio`. Some are behavioral and hard to fake. `endpoint_entropy` measures the Shannon entropy of which endpoints were hit in this window — a real user visits varied routes, a focused attacker hits one endpoint repeatedly. `endpoint_cost_mean` uses the calibrated cost table — if you make 50 search calls, the mean cost is much higher than 50 profile calls. `iat_cv` is the coefficient of variation of inter-arrival times — humans are bursty, bots are regular.
>
> The window size — 10 seconds — was chosen so that detection latency stays low while still giving statistical power per window. Smaller windows are noisy; larger windows hurt latency."

**Switch tab to:** `analysis/scripts/13_tier3_global.py`. Scroll to the system-wide aggregation.

**Say:**

> "Tier 3 is global. For each window, it asks 'what's happening on the *whole system* at this moment?' — `global_unique_ip`, `global_unique_subnet`, `global_new_src_ratio`. The point is: a per-IP view sees one source at a time, but a distributed attack only shows up when you look at the entire window across all sources. This is where the ablation later shows that removing global features drops mimicry recall by about 80 percentage points."

**(Skip Tier 1 and Tier 4 unless asked.)** Mention briefly:

> "Tier 1 is per-connection (duration, partial flag, timeout flag — captures slowloris). Tier 4 is session-level (used only as a feature, not a primary signal). Total of 37 features across the four tiers."

**Connection:** "OK, the features are built. Now let me show you the model and the four independent checks I ran on it."

---

### Stage 8 — Model + evaluation (3–4 min) — **THE LINGER**

**Open:** `analysis/scripts/26_mimicry_holdout_analysis.py`. Scroll to the model fit and the mimicry evaluation.

**Say:**

> "The model is a Random Forest — 200 trees, balanced subsampling for class weights. The choice is deliberate. The contribution of this thesis is the *feature pipeline*, not a novel classifier. Random Forest is well-understood, gives feature importances directly, and has the right capacity for around 7,000 training windows. Deep learning would either overfit at this scale or need much more data.
>
> The four-class supervised label set is `normal_user`, `http_flood`, `low_rate_bot`, `credential_stuffing`. Mimicry is *not* a class. The model has never seen it.
>
> When the model meets a mimicry window at test time, it doesn't predict 'mimicry' — it has to predict one of the four classes it knows. I measure three things: the fraction predicted as `http_flood` — that's `mimicry_recall_as_flood`, 96.38%. The fraction predicted as `normal_user` — that's `mimicry_evasion_rate`, 3.08%. The total fraction predicted as any non-normal class — that's binary attack recall, 96.92%."

**Switch tab to:** `analysis/scripts/28_cross_validation.py`. Scroll to the `StratifiedKFold` and `cross_validate` call.

**Say:**

> "On top of the single train/val/test split, I added 5-fold stratified cross-validation on the combined in-distribution pool — that's about 9,600 windows. Accuracy is 99.94% ± 0.05%, macro-F1 is 99.92% ± 0.05%. The per-fold range is 99.84% to 100%. So the single-split result is not a partition artifact."

**(Open the terminal, optionally run:)**

```bash
cat analysis/data/results/cross_validation_summary.csv
cat analysis/data/results/mimicry_baseline_vs_proposed.csv
```

**Say:**

> "And the ablation — this is in `27_ablation_study.py`. I retrained the model twelve times, each time removing one feature group. Rate-only mimicry recall is 73%. Full pipeline mimicry recall is 96%. That 23-point gap is the behavioral lift — it's evidence the model isn't taking a rate shortcut."

**Connection:** "So the final picture: four independent checks all point the same way. Let me close with what's solid and what's still open."

---

### Stage 9 — Results, limits, contribution (2 min)

**Open:** `docs/attack_calibration_sources.md`. Have it ready in case the advisor asks "where did your parameters come from."

**Say:**

> "Three contributions. First — the multi-tier behavioral feature pipeline. Four tiers, 37 features, +23 percentage points of mimicry recall over rate-only. Second — the mimicry holdout protocol itself. The model never saw S5 during training, and 96.38% recall is the generalization claim. Third — sensitivity-analyzed reporting. I identified two implementation issues during the project — the UserService Prisma client and the missing think-time sleep — and I re-verified the central finding across V1 (with bugs), V2 (bug-fixed but low legit volume), and V3 (bug-fixed with production-realistic legit volume). And on top of that, 5-fold cross-validation confirms stability.
>
> Limitations — honestly: single application, so endpoint cost profile is application-specific. Synthetic traffic, no production trace validation. No adaptive adversary — the mimicry is static, not iteratively optimized against detector feedback. Slow HTTP is sparse because nginx kills it at 60 seconds; evaluated by rule, not supervised.
>
> Future work is in five buckets — multi-application validation, adaptive adversary, production trace validation, protocol-level features like JA3 fingerprints, and richer slow-HTTP telemetry."

**End with:**

> "Hocam, that's the project end-to-end. Anything you want me to open and go deeper on?"

---

## 4. Must-know code blocks

These are the blocks where, if the advisor says *"open the code that produced this"*, you need to know exactly what to point to. Memorize the file name + the function/line region — not the lines themselves.

| File | Block | What to be ready to explain |
|---|---|---|
| `src/middleware/request-logger.middleware.ts` | The `use()` method and `res.on('finish')` callback | How per-request cost is captured and written to RequestLog. Mention `AsyncLocalStorage` keeps `metrics` isolated per concurrent request. |
| `src/common/request-context/request-context.ts` | The `RequestMetrics` interface + AsyncLocalStorage wiring | "This is how dbQueryCount stays attached to the right request even under concurrency." |
| `src/user/user.service.ts` | The constructor (`constructor(private prisma: PrismaService)`) | "Before V2 this was `new PrismaClient()` — bypassed the instrumented client. Fix was one-line constructor injection." |
| `k6/common/legitimate-user-flow.js` | The Markov transition matrix + the `sleep(thinkTime)` call | "Navigation is Markov, think time is log-normal sampled, *then passed to sleep* — V2 fix." |
| `k6/scenarios/05_mimicry_flood.js` | The `state()` function — UA pool, IP pool, token-reuse counter | "Four mimicry levers in one place: UA, IP, token reuse, rate envelope identical to flood." |
| `infra/nginx/nginx.conf` | The `log_format` block + `client_body_timeout 60s` | "JSON log gives me 408s; timeout is what makes slowloris visible at the proxy." |
| `prisma/schema.prisma` | `model RequestLog`, `model Connection`, `model EndpointCostProfile` | The three tables that hold per-request cost, per-connection metadata, and the calibrated cost table. |
| `analysis/scripts/12_tier2_features.py` | The window-aggregation loop (where `endpoint_entropy`, `endpoint_cost_mean`, `iat_cv` are computed) | "10-second window, grouped by IP and /24, this is where behavioral signal is built." |
| `analysis/scripts/13_tier3_global.py` | The global aggregation per window | "System-wide view in the same window — `global_unique_ip`, `global_new_src_ratio`." |
| `analysis/scripts/15_baseline_distance.py` | The `markov_log_likelihood` and `iat_ks_distance` functions | "Distance from NASA reference becomes two features." |
| `analysis/scripts/21_baseline_random_forest.py` | The `RandomForestClassifier(...)` instantiation + the column-drop step | "200 trees, balanced_subsample, drop scenario_id/majority_label to prevent leakage." |
| `analysis/scripts/26_mimicry_holdout_analysis.py` | The mimicry evaluation block (three metrics: recall_as_flood, evasion_rate, binary_attack_recall) | "Mimicry isn't a class — these three numbers are how I score it." |
| `analysis/scripts/27_ablation_study.py` | The feature-group definitions and the loop over them | "Twelve groups, each removed in turn — produces the +23pp behavioral lift." |
| `analysis/scripts/28_cross_validation.py` | The `StratifiedKFold(n_splits=5)` and `cross_validate(...)` block | "5-fold stratified on the combined in-distribution pool — 99.94% ± 0.05%." |

**Things you do NOT need to defend line-by-line:**
- Auth controller/service — it's a JWT API, off-topic
- Metrics module — Prometheus boilerplate
- Test files (`*.spec.ts`) — not part of the research claim
- Logs service — wraps the DB write, no logic worth defending
- `app.module.ts`, `main.ts` — bootstrapping

If the advisor opens one of these, say: *"That's the auth surface — it's a standard JWT controller, not part of the research contribution. The research surface is the middleware, the k6 scenarios, and the analysis pipeline."*

---

## 5. Possible advisor questions — strong answers

### About tooling

**Q: Why k6?**
> "Two reasons. First, k6 is JavaScript-scriptable, so I can encode complex per-VU state — like the mimicry token-reuse counter — without writing my own load generator. Second, the `ramping-arrival-rate` executor decouples request rate from VU count, which matters because I'm controlling traffic intensity, not concurrency. JMeter is XML-config-driven and harder to express stateful logic. Locust would have worked, but k6's per-stage rate ramp matched my scenario design better."

**Q: Why nginx?**
> "Three reasons. One, it's the most common production reverse proxy, so the constraints it imposes are realistic — connection limits, timeouts, buffering. Two, the JSON access log captures requests that never reach the application, especially the 408 timeouts that make slowloris visible. Three, the 60-second `client_body_timeout` is exactly the kind of operational constraint a real deployment would have, which keeps the experiment honest."

**Q: Why Random Forest, not deep learning?**
> "The contribution is the feature engineering, not the classifier. Random Forest is a well-understood, high-capacity classifier that lets the features speak for themselves. With 37 hand-crafted features and around 7,000 training windows, deep learning would either overfit or need orders of magnitude more data. RF also gives feature importance directly, which is critical for the ablation analysis. If the features carry the signal, any strong supervised model should learn them — and that's what RF confirms."

### About real datasets

**Q: Why NASA, ClarkNet, Calgary?**
> "Three reasons. They're public — Internet Traffic Archive — so reproducible. They're widely cited in web measurement work, so my calibration anchors to a known reference. And cross-trace consistency lets me separate *structural* invariants — distribution shape — from *contextual* parameters — exact values. The cross-trace report shows the lognormal shape and Markov structure are stable across NASA Jul vs Aug, and across ClarkNet Aug vs Sep, but parameter values differ between institutions. That's exactly the structural-prior framing in the thesis."

**Q: Why was Calgary excluded from the session-aware analysis?**
> "Calgary was anonymized to two virtual hosts before public release. The host header is what I use to reconstruct user sessions and Markov transitions. With only two hosts, session boundaries are ambiguous, so I excluded Calgary from the session-aware components — IAT lognormal fit, Markov transitions — and kept it only for endpoint Zipf, which is path-level and doesn't depend on session reconstruction. It's documented in the cross-trace consistency report."

### About distribution choices

**Q: What is IAT and why log-normal?**
> "IAT is inter-arrival time — the time between consecutive requests from the same source. Log-normal because it's heavy-tailed: most requests come quickly, but some have very long gaps. NASA Jul95 has μ_log around 2.38 and σ_log around 1.75 — median 9 seconds, mean 55 seconds, 95th percentile 243 seconds. Log-normal also has a clean parameterization for re-fitting; we can keep the *shape* and adjust the parameters for a modern API context. My IAT KS distance against NASA is 0.32 after the V3 bug fix — substantial alignment but not exact replication, which the thesis frames as structural-prior transfer."

**Q: What is Zipf?**
> "Zipf is a power-law distribution over discrete items, here endpoint popularity. The most-popular endpoint gets hit much more than the second-most, and so on, with a heavy tail. NASA's α is 1.25, ClarkNet's is around 0.95, Calgary's is 0.84. Mine fits at 2.20 — sharper, because I have 4 routes versus NASA's hundreds. The *power-law shape* transfers; the *exponent* re-parameterizes."

**Q: What is the Markov chain used for?**
> "The Markov chain models the navigation graph of a legitimate session. States are URL categories — login, search, profile, browse, logout — and the transition probabilities come from the NASA cross-trace analysis. I use it in two ways. One, in the k6 legitimate flow, to drive realistic user navigation. Two, in the analysis pipeline, the `markov_log_likelihood` feature scores how likely the observed sequence is under the legitimate model — low likelihood means anomalous navigation."

### About telemetry and features

**Q: Why are nginx 408 logs important?**
> "Slowloris keeps a connection half-open. The request never completes, so it never reaches the application — the application sees nothing. But nginx, after `client_body_timeout`, kills the connection and writes an access log entry with status 408. Without those log lines, slowloris is invisible. The ingestion script joins those 408 entries onto the Connection table, which is what makes the timeout signal a queryable feature."

**Q: What's the difference between Tier 1 and Tier 2?**
> "Tier 1 is per-connection — duration, request count on this connection, partial-request flag, timeout flag. It's the unit nginx and the kernel see. Tier 2 is per-window — 10-second aggregations per source IP and per /24 subnet, with the behavioral features: rate, entropy, cost, timing. Tier 1 catches connection-shape attacks like slowloris; Tier 2 catches behavioral patterns over time. Tier 3 is global, Tier 4 is session-level. The four tiers look at the same traffic at four different scopes."

### About calibration validity

**Q: How do you know your calibration is valid?**
> "Three pieces of evidence. One, the cross-trace consistency report — intra-institutional spread is small (NASA Jul vs Aug differ by 9% on μ_log), inter-institutional spread is larger (NASA vs ClarkNet differ by 20% on μ_log), exactly the structural-vs-contextual separation. Two, the IAT KS distance dropped from 0.99 in V1 to 0.32 in V3 after the bug fixes — substantial structural alignment. Three, calibration is used as a *feature*, not a ground truth — the Markov log-likelihood and IAT KS distance get fed into the model, and if calibration were wrong, those features wouldn't be informative. Feature importance shows they're not the top, but they're not zero either."

### About limitations

**Q: What are the limitations?**
> "Eight, honestly. Single application — endpoint cost profile is API-specific. Synthetic traffic — no production trace validation, though structural calibration is done. No adaptive adversary — mimicry is static, not iteratively optimized. Slowloris is sparse because nginx kills it at 60 seconds. Auth-layer rate limiting was disabled deliberately, to isolate the behavioral signal. Two implementation bugs identified, corrected, and re-verified across V1/V2/V3 — UserService Prisma client and missing think-time sleep. External validation limited — I looked at CIC-DDoS2019 as a sanity check, but the feature space differs from API-layer behavioral features, so it's a sanity check, not primary validation. All eight are listed in §5.6."

### Trap questions

**Q: 100% in-distribution accuracy looks suspicious.**
> "Three responses. One, a random-label permutation test drops the model from 99.8% to 33% — that 67-point gap is evidence the features carry real signal, not leakage. Two, 5-fold stratified CV gives 99.94% ± 0.05% — the result isn't a single-split artifact. Three, the harder test isn't in-distribution at all — it's the mimicry holdout, 96.38%, on a class the model never saw. That's the number that matters."

**Q: Your traffic is synthetic — is this realistic?**
> "Structurally yes. Log-normal IAT shape, Zipf endpoint popularity, Markov navigation, all calibrated against NASA. IAT KS dropped from 0.99 to 0.32 after V3. Numerically no — NASA has hundreds of routes, my API has 4, so exact values differ. I treat NASA as a structural reference, not a replication target. Production trace validation is in the future work list."

**Q: Why didn't you sweep more parameters? Like the flood rate?**
> "I did sensitivity analysis on the legit side — V1, V2, V3 — because that's where the bug fixes mattered most for the central claim. On the attack side, peak 200 req/s is sourced from Cloudflare 2025 Q1 DDoS Threat Report — that envelope covers 94% of observed L7 attacks at scaled-down lab dimensions. I didn't sweep flood rate because higher rates make detection *easier*, not harder — the harder test is mimicry at the *same* rate, which is exactly what S5 does."

---

## 6. The 10-minute version (compressed)

Use this if the advisor is short on time, distracted, or you sense things are going well and they're ready to wrap up.

| Time | Stage | Files | One-sentence framing |
|---|---|---|---|
| 0:00–1:00 | Research question | (talk only, no file) | "Can a behavior detector survive surface mimicry?" |
| 1:00–2:00 | Architecture | `docker-compose.yml` | Three containers, single controlled data path. |
| 2:00–3:30 | Application & cost capture | `src/middleware/request-logger.middleware.ts`, `prisma/schema.prisma` | "I measure cost per request, not just rate." |
| 3:30–5:30 | Traffic + S5 mimicry | `k6/scenarios/05_mimicry_flood.js` | "Mimicry uses legit UA, overlap IPs, sticky tokens — same rate as flood." |
| 5:30–7:30 | Features & model | `analysis/scripts/12_tier2_features.py`, `analysis/scripts/26_mimicry_holdout_analysis.py` | "10-second windows, 37 features, RF, mimicry holdout 96.38%." |
| 7:30–9:00 | Stability & ablation | `analysis/scripts/28_cross_validation.py`, terminal `cat ablation_study_results.csv` | "5-fold CV 99.94% ± 0.05%, +23pp behavioral lift." |
| 9:00–10:00 | Limits + close | `docs/thesis_methodology.md` §5.6 (optional) | "Two bugs found, re-verified across V1/V2/V3, eight limitations listed." |

Skip in this version: Calibration deep-dive, nginx config, Tier 3 walkthrough, Tier 1/4 mention. If the advisor asks, you have the tabs ready.

---

## 7. The 20-minute version (full)

Use the **9 stages above in order**, with these targets:

- Stage 1 (Research question): 1:30
- Stage 2 (Architecture): 1:30
- Stage 3 (App + cost capture): 2:00
- Stage 4 (Traffic + S5): 4:00 ← **linger here**
- Stage 5 (Calibration): 2:30
- Stage 6 (Ingestion): 1:30
- Stage 7 (Features): 3:30 ← **linger here**
- Stage 8 (Model + eval): 3:30 ← **linger here**
- Stage 9 (Limits + close): 2:00

= 22 minutes. Add 3 min buffer for advisor questions during the walk, target 25 min total.

**Lingers (the slides/files where you slow down):**
- Stage 4: mimicry design — this is where the thesis question lives.
- Stage 7: Tier 2 — this is the most important Python file.
- Stage 8: holdout + CV + ablation — this is where the evidence lives.

**Skim (don't linger):**
- Stage 2: ten seconds on each service.
- Stage 5: one paragraph on cross-trace, one on calibration-as-feature.
- Stage 6: one sentence per telemetry stream.

---

## 8. Pre-flight checklist (5 min before the meeting)

1. Close Slack, mail, Discord.
2. Open VS Code with the project root.
3. Open all 14 tabs in the order from section 2.
4. Open one terminal at the project root.
5. Have `Thesis_Final_Defense.pptx` open in another window in case the advisor asks to see slides.
6. Have a glass of water.
7. Read section 1 (the story arc) one more time. You're not memorizing — you're internalizing the *shape*.
8. Smile, breathe, click into VS Code.

---

## 9. Three things to remember when you lose your place

1. **Every digression returns to mimicry.** If you wander, ask: "How does this connect to 'the model catches an attack it never saw'?" Pivot there.
2. **Numbers anchor you.** When in doubt, cite one: 96.38% mimicry recall, +23pp behavioral lift, FPR zero, 5-fold CV 99.94% ± 0.05%. These are your safety nets.
3. **It's a conversation, not a lecture.** If the advisor's eyes glaze over, ask: *"Does that part make sense, or should I go deeper?"* — it shows confidence, not insecurity.

You wrote this entire system. You found the bugs. You calibrated against three real traces. You ran four independent evaluations. You understand every line of every file that matters.

You don't need to *act* like you know what you're talking about. You actually do.
