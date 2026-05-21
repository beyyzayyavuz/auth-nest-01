# Talk Track — Natural Walkthrough for Tomorrow

**Goal:** Sound natural, conversational, and specific. Every general statement is followed by a clarifying sentence using phrases like *"What I mean is..."* / *"What I'm trying to say is..."* / *"So with that..."* / *"To make it concrete..."* / *"To put it differently..."*

**Time:** ~18–22 minutes for the main walkthrough + ~2-minute opening intro.

**Language:** English throughout.

---

## 🎬 OPENING — Before You Click to Slide 1 (≈90 sec)

Stand at the laptop, smile, slow start.

> *Hocam, good morning. Before I start the actual walkthrough, I want to give you a quick context.*
>
> *In our last meeting I'd mentioned that I would do a real-dataset review before going into the main implementation. What I mean by that is — I wanted to check whether public DDoS datasets like CIC-DDoS2019 would fit my detection setting, because our pipeline runs at the API layer with application-level features, and not all public datasets cover that layer.*
>
> *So I went through CIC-DDoS2019 — specifically the UDPLag subset — and what I found is that it operates at the network flow level, with features like packet counts and flow durations. That feature space is different from mine, which uses route templates, endpoint cost, and login behavior. I still ran a sanity check on CIC, and reported it openly in the thesis as a limited external reference rather than a primary validation. I'll show you the table later when we get to the external validation slide.*
>
> *With that out of the way — what I want to do today is walk you through the entire project, end to end, as if this were the rehearsal for the final defense. The structure will be: the research question, the system architecture, the methodology, the results, the limitations, and the contributions. Around twenty minutes total. If anything catches your eye, please stop me — I'd rather pause and clarify than rush through.*
>
> *Let me share the screen.*

🟢 *(Click to slide 1)*

---

## Slide 1 — Title (≈10 sec)

> *So this is the project: "Behavioral DDoS Detection at the API Layer — Robustness of Behavioral Features under Mimicry Attacks." Let me start with what I've been doing since we last spoke.*

🟢 *(Click)*

---

## Slide 2 — What I've Completed (≈75 sec)

> *This is a quick three-column summary of where the project stands. I won't read everything; I just want to set the ground.*
>
> *On the left — the infrastructure. I built a controlled testbed using NestJS for the application, nginx as the reverse proxy, PostgreSQL for storage. What I mean by "controlled" is that I run the attack scenarios myself using k6 and slowhttptest, so I have ground-truth labels for every single request.*
>
> *In the middle — features and modeling. I built a four-tier feature pipeline with thirty-seven features in total. The thesis contribution here is the feature engineering itself, not a novel classifier. So with that in mind, I trained a Random Forest as the main model, and I also tested a stacked Isolation Forest + Random Forest as a semi-supervised alternative for comparison.*
>
> *On the right — the headline numbers. One hundred percent in-distribution accuracy on the four known attack classes, ninety-six point three percent recall on the mimicry holdout, and a behavioral lift of plus twenty-three percentage points over rate-only features. What I mean by behavioral lift is — when I strip out all the behavioral features and leave only the rate features, mimicry recall drops from ninety-six to seventy-three. That gap is what I'm calling the behavioral lift, and I'll come back to it.*
>
> *I also ran a sensitivity analysis across three experimental configurations, but I'll explain that when we get to the limitations section. Let me start with the actual question.*

🟢 *(Click)*

---

## Slide 3 — The Question in One Sentence (≈50 sec)

> *Here's the one sentence the whole thesis is built around.*
>
> *If an attacker mimics surface features — User-Agent, IP, even request rate — of a real user, can a behavior-based detector still tell them apart?*
>
> *To put it differently — the question is whether a model can catch an attack that has been camouflaged to look exactly like normal traffic at the surface. The three numbered boxes below are the sub-questions: do rate-based defenses suffice; how discriminative are behavioral features; and the strict test — can a model that has never seen mimicry in training still flag it as an attack.*
>
> *The rest of the presentation is the experimental answer to these three.*

🟢 *(Click)*

---

## Slide 4 — Why is This Question Hard? (≈70 sec)

> *Four reasons this is harder than it looks.*
>
> *First, traffic is distributed. What I mean is — Akamai and Cloudflare reports show that a typical Layer 7 attack spans hundreds to thousands of source IPs. So the classical "rate per IP" threshold becomes useless because every single source stays under the limit.*
>
> *Second, attackers mimic surface details. They rotate User-Agents — Chrome, Safari, iPhone — and vary Accept-Language and Accept-Encoding headers. From the outside, the request looks like a normal browser, not a tool.*
>
> *Third, and this one is specific to APIs — cost asymmetry. In my system, calibration shows the /auth/login endpoint costs about one hundred fifty milliseconds because of bcrypt password hashing, while /user/profile costs less than a millisecond. That's roughly two hundred times difference. So just counting requests misses where the actual cost lies.*
>
> *Fourth, the methodological point. If you train your model on every attack type, of course it performs well when you test it on the same types. The honest test is whether it catches a variant it has never seen during training. That's the protocol I designed, and I'll show you how it works in a moment.*

🟢 *(Click)*

---

## Slide 5 — System Architecture (≈60 sec)

> *This is the data path, end to end.*
>
> *Traffic generation on the left — k6 plus slowhttptest, running my six scenarios. That hits nginx, which is the reverse proxy and captures connection-level access logs in JSON format. From nginx, traffic goes to my NestJS application, where a middleware and an interceptor capture per-request backend cost. Everything lands in PostgreSQL — RequestLog at the request level, Connection at the connection level. My feature pipeline produces thirty-seven features per ten-second window. And finally the model — Random Forest as the primary, with the ISO+RF alternative I mentioned.*
>
> *Two technical details worth flagging. The AsyncLocalStorage pattern in Node.js — what it does is isolate per-request metrics cleanly, so database queries belonging to one request never leak into another's measurement. And the connection enrichment step — nginx logs HTTP 408 timeouts when slowloris attempts get killed at the edge. I parse those entries and join them into the Connection table, so slowloris becomes visible to my feature pipeline even though the backend never sees a complete request.*

*If hoca asks "What is AsyncLocalStorage?":*
> *It's a Node.js feature for what's called "context propagation." What it means is — when a request comes in, we open a kind of scope, and any database query or computation that happens inside that scope gets tagged with that request's identifier. So we never accidentally attribute a query from request A to request B's metrics.*

🟢 *(Click)*

---

## Slide 6 — Six Traffic Scenarios (≈90 sec)

> *Six scenarios. Pay attention to the fifth one — that's the special one.*
>
> *S1 is legitimate traffic. What I mean is — a synthetic user that does Markov-driven navigation, log-normal think times, Zipf-distributed search terms. In the V3 configuration I'll explain later, I run one hundred concurrent users for production-realistic baseline.*
>
> *S2 is an HTTP flood — distributed high-rate requests with a naive attacker User-Agent pool, things like curl and python-requests.*
>
> *S3 is a low-rate bot — a persistent scraper deliberately slow, designed to stay below typical rate thresholds.*
>
> *S4 is credential stuffing — random email and password login attempts, which generate strong 401 status signals.*
>
> *S5 is the mimicry flood — and this is the one. The attacker pulls User-Agents from the same pool as legitimate users, uses IPs that overlap with the legitimate IP pool, reuses tokens like a real session, and only bursts on search. So with that, the surface looks legitimate, but the behavior is still flood-level.*
>
> *S6 is slowloris — sparse signals because nginx kills slow connections at sixty seconds.*
>
> *The key design decision is at the bottom — S5 mimicry is excluded from training and validation. It only appears in the holdout test partition. So the model has never seen mimicry until the moment it has to classify it.*

🟢 *(Click)*

---

## Slide 7 — Anatomy of the Mimicry Attack (≈70 sec)

> *Let me zoom in on what makes mimicry different from a naive flood, because this asymmetry is the thesis question in concrete form.*
>
> *On the left, naive flood. User-Agent is curl or python-requests — obviously a tool. IP pool is attacker-specific. Every iteration logs in from scratch. Bursty cadence.*
>
> *On the right, mimicry. User-Agents from the legitimate pool — actual Chrome, Safari, iPhone strings. IPs overlap with legitimate traffic. The attacker reuses tokens, re-logging in only every fifty iterations, like a real session.*
>
> *So what's left for a detector to grab onto? The answer is in the takeaway box at the bottom: the attacker can imitate the surface, but the endpoint distribution, the backend cost asymmetry, and the session pattern are harder to fake. That's the signal we expect the model to catch.*

🟢 *(Click)*

---

## Slide 8 — Four-Tier Feature Engineering (≈80 sec)

> *Thirty-seven features across four tiers. Let me sketch each.*
>
> *Tier 1, connection level. What I mean is — for each TCP connection, I compute duration, request count, whether keepalive was used, and partial/timeout flags. This is where the slowloris signal lives, after the nginx 408 enrichment I mentioned.*
>
> *Tier 2, window level. Ten-second windows, aggregated per source IP and per slash twenty-four subnet. Most of the discriminative signal sits here: request rate, IAT statistics — that's inter-arrival time — endpoint entropy, endpoint cost mean, login presence ratio, 4xx ratio.*
>
> *Tier 3, global level. What's happening system-wide in that same ten seconds — unique IPs, unique subnets, global request rate, ratio of new sources. This catches the spread signature of distributed attacks.*
>
> *Tier 4, baseline distance. Two features comparing the current window to historical NASA web trace baselines: a Markov log-likelihood for navigation patterns, and a KS distance for the inter-arrival time distribution.*
>
> *Together, thirty-seven features, with separate rows for IP-level and subnet-level aggregations.*

*If hoca asks "Why ten seconds for the window?":*
> *It's a tradeoff. Shorter windows give faster detection but noisier signals, longer windows are smoother but slower. Ten seconds is the standard in the L7 detection literature for capturing burst behavior while still being responsive.*

🟢 *(Click)*

---

## Slide 9 — Proposed Approach (≈80 sec)

> *The model has two configurations.*
>
> *On the left, the proposed approach — a supervised Random Forest on the full thirty-seven-feature pipeline. What I want to emphasize here is that the thesis contribution is the feature engineering, not a novel classifier. So Random Forest is a deliberate choice — it's a strong, well-understood baseline that lets the features speak for themselves.*
>
> *On the right, the alternative — a stacked Isolation Forest + Random Forest. What I mean by stacked is — first the Isolation Forest is trained only on normal_user windows, so it learns the shape of normal behavior. Then it produces an anomaly_score for every window, and that score is fed into the Random Forest along with the original thirty-seven features.*
>
> *Here's the interesting finding: under production-realistic conditions, the ISO+RF gives eighty-eight point nine percent mimicry recall, while the supervised RF alone gives ninety-six point four. So with that, the semi-supervised layer becomes redundant when the rate signal is well-separated. I report ISO+RF in the thesis for completeness, but the main model is the Random Forest.*

🟢 *(Click)*

---

## Slide 10 — Evaluation Protocol (≈75 sec)

> *Three independent tests.*
>
> *Test A is in-distribution. Standard stratified train/val/test split on the four known classes. Metrics: accuracy, macro-F1, PR-AUC, confusion matrix. The question this answers is — does the model separate known attack types correctly?*
>
> *Test B is the mimicry holdout. The strict one. S5 is excluded from training entirely. So the model only meets it at test time. Metrics: recall as flood, evasion rate, binary attack recall. The question is — can the model generalize to an attack it has never seen?*
>
> *Test C is leakage and ablation. I do a random-label permutation sanity check — what that means is, I train the model with shuffled labels, and if it still does well, that's a sign of leakage. In my case, real-label accuracy is ninety-nine point eight, permuted is thirty-three, against a class baseline of twenty-five. That sixty-seven-point gap confirms genuine signal. I also do twelve feature-group ablations.*
>
> *The whole argument of the thesis rests on all three pointing the same way.*

🟢 *(Click)*

---

## Slide 11 — In-Distribution Performance (≈60 sec)

> *Three headline numbers — one hundred percent accuracy, one hundred percent macro-F1, one hundred percent mean PR-AUC. So with that, on the four known attack classes, the model has zero errors across one thousand four hundred forty-six test windows.*
>
> *The per-class table shows every class perfect — credential stuffing, http_flood, low_rate_bot, normal_user — precision, recall, and F1 all one point zero.*
>
> *Now the natural skeptical question here is — "is this overfitting?" — and the reading at the bottom addresses it: the random-label permutation sanity check shows the model can't reach this performance with shuffled labels, so the features carry genuine signal. The harder test, which is the next slide and the one after, is mimicry holdout.*

*If hoca asks "100% sounds too good — are you sure there's no data leakage?":*
> *That's a great question, and it's exactly why I ran the permutation sanity check. What it does is — it shuffles the labels randomly, retrains the model, and measures accuracy. If the model still did well, that would indicate leakage — the model would be finding the labels through some shortcut. In my case, with shuffled labels, accuracy drops from ninety-nine point eight to thirty-three percent, against a class baseline of twenty-five. So the sixty-seven-point gap confirms there is no leakage; the features actually carry the signal.*

🟢 *(Click)*

---

## Slide 12 — Confusion Matrix (≈40 sec)

> *The confusion matrix confirms it. All four classes perfect — three hundred ninety-six credential stuffing, three hundred thirty-two http_flood, one hundred forty-five low_rate_bot, five hundred seventy-three normal_user, every single one on the diagonal.*
>
> *Zero off-diagonal errors. Now the harder test follows.*

🟢 *(Click)*

---

## Slide 13 — ★ Mimicry Holdout (≈100 sec)

> *This is the heart of the thesis. The mimicry holdout result.*
>
> *To make it concrete — this attack type was completely excluded from training. The model never saw a single mimicry window during fitting. It only encountered them at test time, in this holdout partition of one thousand two hundred ninety-nine windows.*
>
> *The three numbers — ninety-six point three eight percent of mimicry windows got correctly classified as http_flood. Three point zero eight percent were classified as normal_user — that's the evasion rate. Combined, the binary attack recall is ninety-six point nine two percent.*
>
> *The chart at the bottom compares the proposed Random Forest against the ISO+RF alternative. The supervised RF actually outperforms the stacked model here — that's the redundancy point I mentioned earlier.*
>
> *What this result tells me is that the behavioral features I engineered generalize to an attack variant the model has never been trained on. The features are not memorizing specific attack signatures from training — they're capturing something more general about what attacks behaviorally look like.*

🟢 *(Click)*

---

## Slide 14 — How to Read the Mimicry Result (≈80 sec)

> *Let me unpack what this means in three layers.*
>
> *Layer one — what the attacker did well. Surface mimicry worked. UA pool, IP overlap, token reuse, sticky sessions — all successfully imitated. Per-window request rate actually overlaps with normal_user.*
>
> *Layer two — what the attacker could not fake. Endpoint distribution narrow — the attack only bursts on search. Endpoint cost asymmetry doesn't match real users. Login pattern mechanical. These behavioral signatures bleed through the surface mimicry.*
>
> *Layer three — why this matters. The model never saw the mimicry variant of these features during training. It still flagged ninety-seven percent of mimicry windows as attack. That's the generalization claim — the features carry information that transfers to a new attack type.*

🟢 *(Click)*

---

## Slide 15 — Ablation Study (≈100 sec)

> *Now this slide is just as important as the mimicry one. It answers the question — okay, the model works, but what is it actually relying on?*
>
> *Look at the right column. All features — ninety-six point four percent mimicry recall. Rate-only — seventy-three point one. So the gap is plus twenty-three percentage points, and that's the contribution of behavioral features over rate.*
>
> *To put it differently — even though the rate-only configuration reaches ninety-three percent in-distribution validation accuracy, on the mimicry holdout it drops to seventy-three. So rate is enough to separate the known classes, but it's NOT enough to catch mimicry. The behavioral features are what add the lift.*
>
> *UA-only is at thirteen point two percent — below the class baseline of twenty-five. So the model is definitely not using User-Agent as a shortcut.*
>
> *And removing the global features collapses mimicry recall to fifteen percent — that's an eighty-one-point drop. Global source diversity is essential for capturing the distributed nature of attacks.*
>
> *So with that, the full model genuinely needs the combination of behavioral signals — no single group alone is sufficient, and rate alone in particular is not enough for mimicry.*

🟢 *(Click)*

---

## Slide 16 — Feature Importance (≈50 sec)

> *Top features grouped by category.*
>
> *Source diversity dominates — global_unique_ip, global_unique_subnet, global_req_rate. This reflects the distributed nature of the attacks.*
>
> *Identity and status — login presence ratio and 4xx ratio. Auth pattern and error signal.*
>
> *Endpoint cost — endpoint_cost_mean and endpoint_cost_sum. The backend cost asymmetry I designed.*
>
> *And timing behavior — IAT mean, IAT KS distance. Strong on mimicry, because the ablation showed removing IAT drops mimicry recall by forty-three points.*
>
> *So the model uses a combination of source diversity, identity, cost, and timing — exactly the multi-signal view I designed.*

🟢 *(Click)*

---

## Slide 17 — Mimicry, Flood, and Legit Side-by-Side (≈60 sec)

> *One more deep-dive. Mimicry, naive flood, and legit traffic, side by side across key features.*
>
> *req_rate — overlaps across all three classes. So rate alone cannot tell mimicry from legit.*
>
> *endpoint_entropy — separates. Legit around point nine, mimicry around zero point zero five. Mimicry only bursts on search, so its distribution is narrow.*
>
> *endpoint_cost_sum — separates. The cost asymmetry signal.*
>
> *ua_entropy — inverted. Higher in mimicry than in flood or legit. What's happening here is — the attacker actively diversifies UA strings to look distributed, and that diversification itself becomes a signal.*

🟢 *(Click)*

---

## Slide 18 — Latency and FPR (≈65 sec)

> *Operational metrics.*
>
> *Detection latency summary on the left. Median latency is zero — detection happens in the first ten-second window. Mimicry binary attack recall ninety-seven percent. Behavioral lift twenty-three points. Slow HTTP is sparse, evaluated by a connection-level rule.*
>
> *False positive rate on the right. Out of all normal-user windows, zero false positives. Zero alerts per legitimate IP-minute. So with that, the operational reading is that the system reacts in the first window, catches mimicry without surface shortcuts, and doesn't bother legitimate users at all.*

🟢 *(Click)*

---

## Slide 19 — Calibration (≈55 sec)

> *Quick transparent note on calibration.*
>
> *Two charts. On the left, IAT distribution. The KS statistic between my synthetic legitimate traffic and NASA's nineteen ninety-five trace dropped from zero point nine nine in the initial configuration to zero point three two in V3. That's substantial alignment.*
>
> *On the right, endpoint popularity. Synthetic alpha two point two zero versus NASA one point two five. The shape is preserved — both are Zipf — but the slope is steeper because my API has four routes versus NASA's hundreds.*
>
> *The framing at the bottom: structural properties preserved; numerical parameters re-parameterized per deployment context. NASA is a structural reference, not a target to replicate.*

🟢 *(Click)*

---

## Slide 20 — Scientific Contributions (≈75 sec)

> *Three methodological contributions.*
>
> *One — the multi-tier behavioral feature pipeline. Thirty-seven features across four tiers. The ablation shows plus twenty-three percentage points behavioral lift on mimicry recall over rate-only. That's the empirical case for the pipeline.*
>
> *Two — the mimicry holdout protocol. Testing on an attack variant explicitly excluded from training is not standard in the literature. I define the protocol explicitly and use it as the central experiment.*
>
> *Three — sensitivity-analyzed reporting. I identified two implementation issues during the project, corrected them, and re-verified the central finding across three experimental configurations. That level of methodological transparency is unusual at this level.*

🟢 *(Click)*

---

## Slide 21 — Limitations (≈85 sec)

> *The honest list.*
>
> *Scope — single application. Data — synthetic traffic, no production validation. Adversary — mimicry is static, not adaptive. Signal — slow HTTP is sparse. Auth — application-layer rate limiting was deliberately disabled to isolate the behavioral signal.*
>
> *And the two FIXED items in green. What I mean is — these are implementation issues I identified during the project, corrected, and then re-verified. The first was that UserService was using a separate Prisma client, which bypassed query timing measurement. The second was that the k6 legitimate flow was computing log-normal think times via a helper but never passing them to sleep, so per-VU rates were higher than realistic. Both fixed in V2 and V3.*
>
> *To put it concretely — the sensitivity analysis I mentioned earlier compares three configurations: V1 with the bugs, V2 with the bugs fixed but low legitimate volume, and V3 with bugs fixed and production-realistic legitimate volume. In all three, mimicry recall stays above ninety-one percent and the ablation studies consistently show behavioral features adding discriminative power beyond rate. So the central finding is robust across the implementation conditions.*
>
> *External validation is limited — CIC-DDoS2019 sanity check performed, but the feature space differs from my API-layer model.*

🟢 *(Click)*

---

## Slide 22 — Future Work (≈40 sec)

> *Five natural extensions. Multi-application validation. Adaptive adversary. Production trace validation. Protocol-level features like TLS JA3/JA4 fingerprints. And richer slow HTTP telemetry to model slowloris as a continuous signal rather than sparse timeouts.*

🟢 *(Click)*

---

## Slide 23 — Closing (≈60 sec)

> *To wrap up.*
>
> *The headline verdict: behavior-based API-layer detection is robust to surface mimicry under production-realistic conditions in this controlled setting. Mimicry holdout ninety-six percent detection, false positive rate zero, plus twenty-three percentage points behavioral lift over rate-only, and UA-only ablation at thirteen percent — so the model is clearly not relying on surface shortcuts.*
>
> *Three takeaways. One — the mimicry holdout protocol is the methodological core; the model generalizes to an unseen attack. Two — the ablation rules out shortcut learning. Three — implementation issues were identified, corrected, and re-verified across three configurations.*
>
> *That's the project. I'm happy to discuss any of it — the methodology, the results, the limitations — wherever you'd like to dig in.*

---

# 🤔 ANTICIPATED Q&A — Technical Questions Your Advisor Might Ask

Read these once or twice. Internalize the structure: short direct answer + one clarifying sentence.

---

## Q: "What's a Parquet file?"

> *Parquet is a columnar storage format. What I mean is — instead of storing data row-by-row like a CSV, Parquet stores each column separately. So when you only need a few columns out of many, reading is much faster. I use it because my feature matrices have thirty-seven columns and tens of thousands of rows, and Parquet compresses better than CSV. It's the standard format in the Python data science ecosystem — pandas, pyarrow, etc.*

## Q: "Can I see the code?"

> *Of course, hocam. Let me alt-tab. The code lives in three main places — `src/` for the NestJS application, `analysis/scripts/` for the thirty Python scripts that handle feature extraction and model training, and `k6/` for the traffic generation scenarios. Which part would you like to see first?*

*If hoca picks something:*
> *(Open the file in VS Code, scroll to the relevant section, explain in 2-3 sentences.)*

## Q: "How do you open these data files? What program?"

> *I use VS Code as the editor. For Python, I have a virtual environment activated — that's a project-local Python install — and I open Parquet or CSV files using pandas. For example, `pd.read_parquet('analysis/data/results/table4_mimicry_holdout.csv')` and then I look at it as a dataframe. If you want, I can open one right now and show you.*

## Q: "What IDE are you using?"

> *Visual Studio Code for everything. The TypeScript side has IntelliSense from the language server, and the Python side uses the Python extension with my virtual environment selected. I run the NestJS app with `npm run start:dev` in one terminal and the Python pipeline with `python analysis/scripts/...` in another.*

## Q: "Where do the numbers in the slides come from?"

> *Every number on the slides is generated by one of the Python scripts and saved as a CSV under `analysis/data/results/`. For instance, the mimicry holdout numbers come from `mimicry_baseline_vs_proposed.csv`, which is produced by script number twenty-six. I can open it if you'd like.*

## Q: "Why did you choose Random Forest and not a deep learning model?"

> *Three reasons. First, the thesis contribution is the feature engineering, not the classifier. So I wanted a strong but well-understood baseline that lets the features speak. Second, with thirty-seven hand-crafted features and around seven thousand training windows, Random Forest is the right capacity — deep learning would overfit or need much more data. Third, RF gives feature importance directly, which is critical for the ablation study and for interpretability.*

## Q: "What if the attacker is adaptive?"

> *That's the next step beyond this thesis, and I list it in Future Work. What I mean by adaptive is — the attacker observes which features the detector uses, and iteratively optimizes endpoint, IP, and timing choices to evade. My current setup tests a static mimicry attack. An adaptive adversary would require an adversarial training loop, which I'd structure as a future experiment with the same feature pipeline.*

## Q: "Is your synthetic traffic realistic enough?"

> *Two levels of answer. At the structural level — log-normal IAT shape, Zipf endpoint popularity, Markov navigation graph — yes, the synthetic traffic follows the same shapes as the NASA 1995 reference, and the KS statistic improved from zero point nine nine to zero point three two after the bug fixes and the scaling to one hundred concurrent users. At the parameter level — alpha is two point two for me versus one point two five for NASA — no, the numerical values differ because my API has four routes versus NASA's hundreds. So I treat NASA as a structural reference, not a replication target. Production trace validation is in the future work list.*

## Q: "What happens if a legitimate user does something suspicious?"

> *That's the false positive rate question. In V3, across two thousand six hundred plus normal user windows, the model produced zero false positives — zero alerts per legitimate IP-minute. The model isn't flagging based on any single suspicious feature; it needs the combination of source diversity, endpoint pattern, timing, and cost signals together. A legitimate user doing a normal session doesn't trigger any of those in combination.*

## Q: "How many hours did the experiments take?"

> *Total compute for V3 was about six to eight hours of traffic generation — six scenarios at roughly thirty minutes each, plus feature pipeline scripts and model training, plus the figures. The setup and bug-fix iterations across the project took longer cumulatively. The data is preserved in backups, so if I need to re-run anything, I can.*

## Q: "Why didn't you use a public dataset?"

> *I did — CIC-DDoS2019, the UDPLag subset. The challenge is that public DDoS datasets are mostly at the network flow level, with features like packet counts and flow durations. My detector uses application-layer features like route templates, endpoint cost, login behavior. So the feature spaces don't align. I ran a sanity check on CIC and reported it as a limited external reference, but full external validation requires application-layer production traces, which is in the future work list.*

## Q: "What's the difference between V1, V2, and V3?"

> *V1 is the initial configuration with two implementation bugs. V2 is bug-fixed but with the original low legitimate VU count. V3 is bug-fixed plus scaled to one hundred concurrent legitimate users for production-realistic baseline. The sensitivity analysis in Discussion section five point seven compares all three. The central finding — behavioral features adding discriminative power on the mimicry holdout — holds across all three configurations.*

## Q: "What's `sleep()` and why was it a bug?"

> *In k6, which is a JavaScript-based load testing tool, `sleep()` is a function that pauses the virtual user for a given number of seconds. My traffic generator computed log-normal think times using a helper called THINK — like THINK.short() that returns a number of seconds. The bug was that I was calling THINK.short() but discarding the return value, instead of passing it to sleep(). So the synthetic users were sending requests with no pause between them. After the fix, every THINK.x() call is wrapped in sleep().*

## Q: "How does the Isolation Forest work?"

> *Isolation Forest is an unsupervised anomaly detection method. What it does — it builds many random decision trees, and anomalous points end up being isolated in fewer splits than normal points. So you get an "anomaly score" for each window. In my setup, I trained the Isolation Forest only on normal_user windows, so it learned the shape of normal behavior, and then it produced an anomaly score for the windows that the Random Forest sees as an extra feature.*

## Q: "Did you compare against any published model?"

> *Not directly — I compared against three classical baselines: per-IP rate threshold, EWMA/CUSUM statistical change detection, and a default Random Forest without class weighting. The published L7 DDoS models I reviewed in the literature don't operate at the same application-layer feature space, so a direct apples-to-apples comparison isn't possible without re-implementing them under matched conditions. That's part of the future work list.*

---

# ✅ Final Pre-Talk Checklist (read 30 seconds before you start)

- [ ] PPTX opens in slideshow mode (F5 in PowerPoint, ⌘+⇧+↩ in Keynote)
- [ ] Browser/IDE windows arranged for code-show emergencies
- [ ] Water bottle nearby
- [ ] Smile, breathe, **start with the opening intro** before slide 1
- [ ] Numbers to remember: **96.38% mimicry · +23pp behavioral lift · FPR = 0 · 100% in-dist · UA-only 13%**
- [ ] If you get a question and don't know the answer: *"That's a great question — let me check after the session and follow up."* — perfectly acceptable, jüri-friendly.

İyi şanslar. 🎯
