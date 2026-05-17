# Thesis Checkpoint — Speaker Script

**Total target time:** ~18–22 minutes (you can shorten any slide if pressed for time)
**Tone:** natural, conversational, confident — like you're explaining the work to a curious colleague, not reading from notes.
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
> **First, the infrastructure and traffic side.** I built the full pipeline — NestJS as the application, nginx as the reverse proxy, PostgreSQL for storage. For every single HTTP request I capture per-request backend cost using AsyncLocalStorage — so things like database time, CPU time, and query counts are isolated cleanly per request. And I run two parallel telemetry streams: nginx access logs at the connection layer, and Prisma RequestLogs at the application layer. On top of that I wrote six k6 traffic scenarios covering legitimate users, HTTP flood, low-rate bot, credential stuffing, mimicry flood, and slowloris.
>
> **Second, features and modeling.** I built a four-tier feature pipeline — connection level, window level, global level, and a baseline-distance layer using historical web traces. I trained both a baseline Random Forest and a stacked Isolation Forest plus Random Forest model. Crucially, the mimicry scenario was never shown during training — it's strictly a holdout.
>
> **Third, evaluation and writing.** The model hits 99.14% test accuracy in-distribution and, more importantly, catches about 92% of mimicry windows even though it never saw them. The ablation study shows that UA-only features land at 9%, rate-only at 71%. And all the thesis chapters — abstract, methodology, results, discussion, conclusion — are drafted.
>
> So with that context, let me take you through the whole project, start to finish.

*Tip: this is the "catch-up" slide. Be brisk but clear. The professor needs to know "she's caught up" without you saying "I was behind."*

---

## Slide 3 — The Question in One Sentence (≈60 sec)

> Here's the one sentence the whole thesis is built around.
>
> **If an attacker mimics surface features — User-Agent, IP, even request rate — of a real user, can a behavior-based detector still tell them apart?**
>
> That question breaks down into three sub-questions, which I've put on the right.
>
> One — are the classical rate-based defenses we all rely on actually enough when the attack is distributed? Two — how discriminative are behavioral features, especially ones like endpoint cost asymmetry? And three — and this is the strict test — can a model that has never seen mimicry during training still flag it as an attack?
>
> The whole rest of the presentation is essentially the experimental answer to these three.

*Tip: pause briefly after reading the main quote. Let it sit.*

---

## Slide 4 — Why is This Question Hard? (≈75 sec)

> Let me ground why this question is harder than it might sound.
>
> **First, traffic is distributed now.** When you read the Akamai or Cloudflare DDoS reports, a typical Layer 7 attack today spans hundreds to thousands of source IPs. That means simple "rate per IP" thresholds are essentially useless — every individual IP stays under the limit.
>
> **Second, attackers mimic surface details.** They rotate User-Agent strings — Chrome, Safari, iPhone, all mixed in. They vary Accept-Language, Accept-Encoding. From the outside, the request looks like a normal browser.
>
> **Third, and this one I find really interesting — cost asymmetry.** An /auth/login request goes through bcrypt password hashing — it can be five hundred times more expensive than a /health check. So just counting requests isn't enough. You need to know *which* endpoints are being hit and *at what cost*.
>
> **Fourth, and this is the methodological point** — if you train your model on every attack type, of course it does well on a test set that contains the same attacks. The honest test is whether it catches a variant it has never seen. That's the heart of what I designed.

*Tip: the fourth point is where you set up the mimicry-holdout protocol. Lean into it.*

---

## Slide 5 — System Architecture (≈60 sec)

> Here's the system end to end, in one strip.
>
> Traffic generation on the left — k6 plus slowhttptest, running my six scenarios. That hits nginx, which is the reverse proxy and also where I capture the connection-level access log in JSON format. From nginx, traffic goes to my NestJS application, where a middleware and an interceptor capture every request's backend cost. Everything lands in PostgreSQL — two main tables, RequestLog at the request level and Connection at the connection level. From there, my feature pipeline produces 37 features per window. And finally the model — the stacked ISO plus RF detector.
>
> A couple of details worth mentioning quickly. The AsyncLocalStorage pattern lets me isolate per-request metrics cleanly, so database queries belonging to one request never leak into another. And the connection enrichment step — nginx logs HTTP 408 timeouts when slowloris attempts get killed at the edge. I parse those and join them into the Connection table, so slowloris becomes visible to my feature pipeline even though the backend never sees the request.

*Tip: don't read the bottom paragraphs verbatim. Use them as memory hooks.*

---

## Slide 6 — Six Traffic Scenarios (≈90 sec)

> Six traffic scenarios in total. Let me walk through them, but pay attention to the fifth one — that's the special one.
>
> **S1, legitimate** — a synthetic user that does Markov-driven navigation, log-normal think times, Zipf-distributed search terms. This is the baseline of "normal."
>
> **S2, HTTP flood** — a distributed high-rate attack, but coming from a naive attacker UA pool — curl, python-requests, Go HTTP client. Easy to spot if you look at the UA.
>
> **S3, low-rate bot** — a persistent scraper, deliberately slow, designed to stay below typical per-IP rate thresholds.
>
> **S4, credential stuffing** — random email and password login attempts. Generates a strong 401 status signal.
>
> **S5, mimicry flood** — and this is the one. This attacker pulls User-Agents from the same pool as legitimate users, uses IPs that overlap with the legit IP pool, reuses tokens like a real session, and only bursts on search. Surface features look legitimate. Behavior is still flood-like.
>
> **S6, slowloris** — and this one is treated separately because nginx kills slow connections at 60 seconds, so it only produces sparse signals.
>
> And here's the key design decision at the bottom — **S5 mimicry is excluded from training and validation. It only appears in a holdout test partition.** That's how I measure generalization to an unseen attack.

*Tip: the design decision callout at the bottom is the main message. Slow down for that line.*

---

## Slide 7 — Anatomy of the Mimicry Attack (≈75 sec)

> Let me zoom in on what makes mimicry different from a naive flood, because this asymmetry is the whole thesis question in concrete form.
>
> On the **left**, the naive HTTP flood. The User-Agent is something like curl or python-requests — obviously a tool. The IP pool is attacker-specific with minimal overlap. Every iteration logs in from scratch. The cadence is bursty, 10 to 50 milliseconds between requests.
>
> On the **right**, mimicry. User-Agents come from the legitimate pool — actual Chrome, Safari, iPhone strings. IPs overlap with legit traffic. The attacker reuses tokens, re-logging in only every 50 iterations to mimic a real session. The cadence still looks bursty, but it sits inside legit-looking sessions.
>
> So the question becomes — what's left for a detector to grab onto? And the answer at the bottom is the thesis claim: the attacker can imitate the surface, but the endpoint distribution, the backend cost asymmetry, and the session pattern are harder to fake. That's the signal we expect the model to learn.

*Tip: this is your setup for why behavioral features matter. Sell it.*

---

## Slide 8 — Four-Tier Feature Engineering (≈90 sec)

> Here's the feature pipeline, organized into four tiers. Each tier looks at a different context, and together they produce 37 numerical features.
>
> **Tier 1, connection level.** For each TCP connection: duration, request count, whether keepalive was used, partial and timeout flags. This is where the slowloris signal lives, after the nginx 408 enrichment.
>
> **Tier 2, window level.** 10-second windows, per source IP and per /24 subnet. This is where most of the discriminative signal sits: request rate, IAT coefficient of variation, endpoint entropy, endpoint cost mean, login presence ratio, 4xx ratio.
>
> **Tier 3, global level.** What's happening system-wide in that same 10 seconds — unique IPs, unique subnets, global request rate, and the ratio of new sources. This catches the spread signature of distributed attacks.
>
> **Tier 4, baseline distance.** Two features comparing the current window to historical web trace baselines from NASA: a Markov log-likelihood for navigation patterns, and a KS distance for the inter-arrival time distribution.
>
> Together, 37 features, with separate rows for IP-level and subnet-level aggregations.

*Tip: don't dwell. Mention each tier in one sentence and move on.*

---

## Slide 9 — Proposed Model: ISO + RF (≈60 sec)

> The model has two stacked layers.
>
> **Layer A is an Isolation Forest.** It's trained *only* on normal-user traffic — so it's semi-supervised. Its job is to learn the shape of normal behavior and produce one extra feature called anomaly_score: high score means the window looks unusual.
>
> **Layer B is a Random Forest.** Supervised, four classes — normal user, HTTP flood, low-rate bot, credential stuffing. It gets the original 37 features *plus* the anomaly score from Layer A.
>
> And I compare this stacked model against a baseline RF that uses only the 37 features without the anomaly score, so I can measure exactly what the extra layer buys me.
>
> The intuition for stacking: the unsupervised layer learns "what normal looks like"; the supervised layer maps deviations into specific attack categories. The two together gave consistent results both in-distribution and on mimicry.

*Tip: the comparison framing matters — it's how you justify "proposed" vs "baseline."*

---

## Slide 10 — Evaluation Protocol (≈75 sec)

> I evaluate the model through three independent tests.
>
> **Test A — in-distribution.** Standard stratified train, validation, test split on the four known classes. Metrics are accuracy, macro-F1, PR-AUC, and a confusion matrix. The question this answers is: does the model separate known attack types correctly?
>
> **Test B — the mimicry holdout.** This is the strict one. Mimicry is excluded from training entirely; the model only meets it during testing. The metrics here are recall-as-flood, evasion rate, and binary attack recall. The question: can the model also catch an attack type it has never seen?
>
> **Test C — leakage and ablation checks.** I run a random-label permutation as a sanity check, plus 12 feature-group ablation experiments. The metrics measure how much the model degrades when you remove or isolate specific feature groups. The question: is the model learning real signal, or is it taking some shortcut?
>
> Three independent exams. The whole argument of the thesis rests on all three pointing the same way.

*Tip: this is a methodology slide. Be precise.*

---

## Slide 11 — Result 1, In-Distribution (≈75 sec)

> Alright, results. Let me start with in-distribution performance.
>
> Three headline numbers: 99.14% test accuracy, 99.23% macro-F1, and the mean PR-AUC across classes is 99.92%. So on the four known attack classes, the model is essentially solving the problem.
>
> Looking at the per-class table — credential stuffing is perfect, 1.0 across the board. http_flood and normal_user are both around 98.7%. Low-rate bot has perfect recall.
>
> And the reading at the bottom — the only errors live between http_flood and normal_user, which makes sense, because distributed flood and high-rate legit traffic genuinely overlap. The other two classes separate cleanly.

*Tip: don't read the table cell by cell. Just point to the pattern.*

---

## Slide 12 — Confusion Matrix (≈60 sec)

> The confusion matrix confirms the pattern. The diagonal is dense — 378 credential stuffing windows all correct, 489 http_flood correct, 76 low-rate bot correct, 448 normal user correct.
>
> The off-diagonal — 6 http_flood predicted as normal, 5 normal predicted as flood, and 1 normal predicted as low-rate. That's 11 errors out of 1403 windows — about 0.8% error.
>
> The important thing is the error pattern: no confusion between credential stuffing and anything else, no confusion between low-rate bot and flood. All the residual noise is concentrated in that overlap zone between flood and legit, which is expected.

*Tip: use the image, don't compete with it.*

---

## Slide 13 — ★ Mimicry Holdout (≈120 sec)

> And here we are — the heart of the thesis. The mimicry holdout result.
>
> Just to be crystal clear about what happened: this attack type was completely excluded from training. The model never saw a single mimicry window during fitting. It only encountered them during the test phase.
>
> The three numbers — **91.96% of mimicry windows got correctly classified as http_flood.** That's the big one. **5.74% were classified as normal_user — that's the evasion rate.** And combining the windows that got mapped to *any* attack class, **the binary attack recall is 94.26%.**
>
> The chart at the bottom compares the baseline RF against my proposed ISO+RF model on the mimicry holdout. They behave very similarly — both reach the low-90s on http_flood, both miss around 5-6% as legit. The Isolation Forest layer gives a small but consistent improvement.
>
> What this result tells me is that the behavioral features I engineered generalize to an attack variant the model has never been trained on. The features are not memorizing specific attack signatures from training — they're capturing something more general about what attacks behaviorally look like.

*Tip: this is THE slide. Slow down, look at the audience, let the numbers land.*

---

## Slide 14 — How to Read the Mimicry Result (≈90 sec)

> Let me unpack what this result means in three layers, because it's important to interpret it carefully.
>
> **Layer one — what the attacker did well.** Surface mimicry worked. The User-Agent pool, the IP overlap, the token reuse, the sticky sessions — all successfully imitated. If you look at the per-window request rate distribution, mimicry actually overlaps with normal_user.
>
> **Layer two — what the attacker could *not* fake.** The endpoint distribution is narrow — the attack only bursts on the search endpoint. The endpoint cost asymmetry doesn't match real users. The login pattern is mechanical. The status-code mix tells its own story. These behavioral signatures bleed through the surface mimicry.
>
> **Layer three — why this matters.** The model never saw the mimicry variant of these features during training. It still flagged 94% of mimicry windows as attack. That's the generalization claim — the features carry information that transfers to a *new* attack type, not just the ones the model memorized.

*Tip: this is the interpretive slide that frames the result correctly for the professor.*

---

## Slide 15 — ★ Ablation Study (≈90 sec)

> Now this slide is just as important as the mimicry one, because it answers the question — okay, the model works, but *what is it actually relying on?*
>
> I ran 12 different ablation experiments. Each one uses a different subset of features. The bars on the left show validation accuracy.
>
> The findings on the right tell the story.
>
> **UA-only — 9.5%.** That's below even the random class baseline of 20%. The model is *not* using User-Agent features as a shortcut.
>
> **Rate-only — 71.3%.** Decent, but far from full performance. So the model is not just leaning on request rate either.
>
> **Endpoint-only — 93.3%.** Endpoint behavior alone is strong. This is one of the bigger sources of signal.
>
> **Full feature set — 99.4%.** Combining everything gives the best, most balanced result.
>
> This rules out the cheap criticism — "your model just learned to spot tool-like User-Agents" or "your model just learned high rate equals attack." Neither is true. The model genuinely needs the combination of behavioral signals.

*Tip: this slide does heavy lifting in defending the thesis claim. Sell each number.*

---

## Slide 16 — Feature Importance (≈60 sec)

> And here are the actual top features, grouped by category.
>
> **Endpoint behavior dominates** — endpoint entropy is the number one feature, and three more endpoint-related features appear in the top ten.
>
> **Identity and status** — login presence ratio is number two, status 4xx ratio is number four. These pick up the "is this an authenticated session" and "is this generating errors" signals.
>
> **Source distribution** — global unique subnet at number five. This is the "is this attack distributed across many sources" signal.
>
> **Backend cost** — mean database time and mean CPU time at eight and nine. These are the actual server-side load measurements.
>
> So the model's attention is exactly where I designed it to be — on the behavioral asymmetries, not on the surface features.

*Tip: short slide, don't linger.*

---

## Slide 17 — Mimicry, Flood, and Legit — Side by Side (≈60 sec)

> One more deep-dive comparison. This shows the feature distributions for mimicry, naive flood, and legit traffic, all side by side.
>
> Look at the verdicts on the right.
>
> **req_rate — overlaps.** All three classes have similar rate distributions. Rate alone cannot separate mimicry from legit.
>
> **endpoint_entropy — separates.** Legit sits around 1.6, mimicry around 0.2. Mimicry only bursts on search, so its endpoint distribution is narrow.
>
> **endpoint_cost_sum — separates.** Legit is high, mimicry is low. The endpoint pattern can't fake the cost asymmetry.
>
> **ua_entropy — inverted.** Higher in mimicry than in flood or legit. The attacker actively diversifies UA strings, and that itself becomes a signal.
>
> This is the granular evidence behind why the model catches mimicry — the behavioral features land on different distributions than the legit class.

*Tip: this is a "show, don't tell" slide. The image does most of the work.*

---

## Slide 18 — Latency and FPR (≈75 sec)

> Operational metrics. How fast does the system detect, and how often does it bother real users?
>
> **Detection latency.** Median is zero seconds — meaning detection happens in the first 10-second window. http_flood, credential stuffing, and mimicry all detect in the first window. The low-rate bot scenario takes about 10 seconds, which is one window — expected, because its behavior is the closest to normal. Slow HTTP is marked sparse and footnoted to the discussion.
>
> **False positive rate.** Out of 2,642 normal-user windows, 8 got flagged as attack. That's 0.018 false positives per legitimate IP-minute. Translated to operational terms — a normal user would see less than two stray alarms per minute, which is production-acceptable.
>
> The takeaway at the bottom — the system reacts immediately on flood and credential stuffing, has acceptable false-positive volume on normal traffic, and the slow HTTP case is honestly limited by nginx behavior, not by the model.

*Tip: the operational reading is what the professor cares about for "would this work in production."*

---

## Slide 19 — Calibration Honesty (≈60 sec)

> Now an honest note on calibration.
>
> The two charts compare my synthetic traffic against the NASA 1995 web trace, which I used as a reference. On the left, the IAT distribution doesn't match — the KS statistic is 0.994, which is very high. On the right, the Zipf endpoint popularity also differs — my synthetic alpha is 1.71, NASA's is 1.25.
>
> The honest framing in the box at the bottom — **synthetic traffic does NOT replicate NASA, and that's expected.** NASA was a broad public web server in 1995, hundreds of paths. My system has four routes, focused API. Exact distributional match would be meaningless.
>
> What I argue is preserved: the *shape* — log-normal IAT, Zipf endpoint popularity, Markov navigation graph structure. What's not preserved: the *numerical parameters* — μ_log, α — which I treat as application-context dependent and re-parameterize. This is the structure-versus-context distinction I develop in the discussion chapter.

*Tip: leaning into the limit transparently is a strength, not a weakness.*

---

## Slide 20 — Scientific Contributions (≈75 sec)

> Three methodological contributions that I think make this thesis stand out from the standard DDoS detection paper.
>
> **One — the mimicry holdout protocol itself.** Testing on an attack variant explicitly excluded from training is not the standard approach in this literature. Most papers train and test on the same attack types. I define the protocol explicitly and use it as the central experiment.
>
> **Two — endpoint-cost-aware feature engineering.** Most work counts requests. I capture per-route backend cost via timing telemetry — database time, CPU time — and fold that into the window features. This is what gives the model its grasp of asymmetric attacks.
>
> **Three — nginx 408 enrichment for slow HTTP.** Slowloris connections die at nginx before the backend middleware sees them. The fix is to pull 408 entries from the nginx access log and join them into the Connection table — so reverse-proxy telemetry feeds the application-layer feature pipeline. This kind of cross-layer instrumentation is rarely documented.

*Tip: this slide positions the thesis academically. Speak with conviction.*

---

## Slide 21 — Limitations (≈90 sec)

> And here is the honest list of limitations. I want to walk through each because transparency is important.
>
> **Scope** — all results are from one NestJS API. The endpoint cost profile is application-specific.
>
> **Data** — synthetic traffic generated in a controlled lab. No production trace validation.
>
> **Adversary** — the mimicry attacker is static. They don't iteratively optimize against detector feedback.
>
> **Signal** — slow HTTP appears as sparse timeout windows because of nginx behavior, so it's evaluated by rule rather than as a supervised class.
>
> **Auth** — I deliberately disabled the application-layer rate limiting and account lockout. This was to isolate the behavioral signal. In production, both layers would coexist.
>
> **Bug one** — the k6 legit flow computes think times but doesn't apply them via sleep. So legitimate traffic in my experiments has higher per-VU rate than realistic production legit. Importantly, this makes the detection problem *harder*, not easier — the model couldn't take a rate-based shortcut, which is consistent with the ablation rate-only result of 71%.
>
> **Bug two** — UserService uses a separate Prisma client, so search endpoint query timings are under-captured. Endpoint cost asymmetry is therefore modeled as a relative-categorical signal rather than absolute timings.
>
> **External validation** — I did a CIC-DDoS2019 sanity check, but it's flow-level — not direct validation of my API-layer model, because the feature spaces differ.

*Tip: don't rush this slide. Limitations openly discussed = credibility.*

---

## Slide 22 — Future Work (≈45 sec)

> Five natural extensions of this thesis.
>
> Multi-application validation — test the same pipeline on 3 to 5 APIs.
>
> Adaptive adversary — let the attacker optimize against detector feedback.
>
> Production trace validation — anonymized real API logs.
>
> Protocol-level features — TLS fingerprints, HTTP/2 behavior, browser automation traces.
>
> Richer slow HTTP telemetry — to model slowloris as a continuous signal.

*Tip: brisk. Just list them.*

---

## Slide 23 — Closing (≈60 sec)

> To wrap up.
>
> The headline verdict: **behavior-based API-layer detection is robust to surface mimicry, in this controlled setting.** Mimicry holdout 91.96% detection, ablation rate-only 71%, UA-only 9%, full feature set 99%.
>
> Three takeaways. **One** — the mimicry holdout protocol is the methodological core; the model genuinely generalizes. **Two** — the ablation rules out shortcut-learning; neither UA nor rate alone is enough. **Three** — limitations including the two code-level bugs are transparently logged in Discussion §5.6.
>
> That's the project. I'm happy to discuss any of it — the methodology, the results, the limitations — wherever you'd like to dig in.

*Tip: end on the invitation. Don't ask "any questions?" — say "I'm happy to discuss any of it." It's a stronger close.*

---

## General Speaker Tips

- **Don't memorize this script.** Read it once or twice, internalize the *shape* of each slide's message. Then deliver in your own words.
- **Numbers you must NOT forget:** 99.14% in-distribution accuracy, 91.96% mimicry recall, 5.74% mimicry evasion, 94.26% binary attack recall, 9% UA-only ablation, 71% rate-only ablation.
- **If asked something you don't know:** "That's a great question — let me check after the session" is a perfectly acceptable answer.
- **Hostile question about the bugs:** lead with "I documented these openly in §5.6 because…" — that immediately reframes from defense to transparency.
- **Hostile question about synthetic traffic:** "Production validation is explicitly listed as future work. The controlled setting was a deliberate methodological choice so I could run the ablation and holdout experiments under matched conditions."

Good luck.
