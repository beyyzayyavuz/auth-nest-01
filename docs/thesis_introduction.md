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