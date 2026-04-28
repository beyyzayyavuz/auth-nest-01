-- ============================================================
-- DDoS Research Project — PostgreSQL Schema
-- ============================================================
-- Tasarım kararları:
--
-- 1. requests tablosu Tier 0 raw'ı tutar. Connection-level (Tier 1) ve
--    windowed (Tier 2) feature'lar offline computed; ayrı materialized
--    table'lar olarak v2'de gelir. v1'de Pandas batch ile in-memory.
--
-- 2. Partition: bucket_1s üstünden RANGE partition. Deney bir hafta
--    sürerse günlük partition yeter. Hızlı drop ve query selectivity için.
--
-- 3. Index strategy: tüm sorgular (src_ip, time) ya da (src_subnet_24, time)
--    erişimi yapacak. Bu iki index zorunlu.
--
-- 4. label kolonu PER-REQUEST. Per-(key, window) label offline'da
--    türetilecek (ayrı tablo: window_labels).
--
-- 5. PII: cookie değeri loglanmıyor. Sadece presence ve hash'lenmiş
--    session_id.
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pg_trgm;  -- ua_family fuzzy search için ileride

-- ============================================================
-- SCENARIOS (deney metadata)
-- ============================================================
CREATE TABLE scenarios (
    scenario_id        VARCHAR(64) PRIMARY KEY,
    name               VARCHAR(128) NOT NULL,
    description        TEXT,
    started_at         TIMESTAMPTZ NOT NULL,
    ended_at           TIMESTAMPTZ,
    -- composition: hangi traffic class'lardan ne yoğunlukta
    legitimate_workers INT,
    flood_workers      INT,
    slowloris_workers  INT,
    slow_post_workers  INT,
    notes              TEXT
);

-- ============================================================
-- REQUESTS (Tier 0 raw)
-- ============================================================
CREATE TABLE requests (
    id                       BIGSERIAL,
    scenario_id              VARCHAR(64) NOT NULL REFERENCES scenarios(scenario_id),

    -- timing
    t_recv_start             TIMESTAMPTZ NOT NULL,
    bucket_1s                TIMESTAMPTZ NOT NULL,  -- date_trunc('second', t_recv_start)
    t_handler_start          TIMESTAMPTZ,
    t_handler_end            TIMESTAMPTZ,
    t_response_complete      TIMESTAMPTZ,

    request_time_ms          INT,            -- nginx total
    upstream_connect_time_ms INT,
    upstream_header_time_ms  INT,
    upstream_response_time_ms INT,

    -- source
    src_ip                   INET NOT NULL,
    src_subnet_24            INET NOT NULL,  -- network(set_masklen(src_ip, 24))
    src_subnet_16            INET NOT NULL,
    src_port                 INT,
    asn                      INT,            -- nullable, MaxMind lookup
    country                  VARCHAR(2),

    -- connection
    conn_id                  BIGINT NOT NULL,
    conn_request_index       INT NOT NULL,
    server_protocol          VARCHAR(16),    -- HTTP/1.1, HTTP/2, etc.

    -- TLS (v1'de cipher/protocol; JA3 v2'de)
    tls_version              VARCHAR(16),
    tls_cipher               VARCHAR(64),

    -- request fingerprint
    method                   VARCHAR(8),
    path_route               VARCHAR(255),   -- NestJS matched route template (KEY)
    path_raw_hash            VARCHAR(64),    -- sha256 of full path+query
    query_str_len            INT,
    body_len_received        INT,

    -- headers (presence only; raw values asla loglanmıyor)
    ua_family                VARCHAR(64),
    ua_raw_hash              VARCHAR(64),    -- sha256, cardinality ölçümü için
    referer_present          BOOLEAN,
    referer_origin_match     BOOLEAN,
    accept_lang_present      BOOLEAN,
    accept_enc_present       BOOLEAN,
    accept_set_hash          VARCHAR(32),
    cookie_present           BOOLEAN,
    session_cookie_present   BOOLEAN,

    -- response
    status                   INT,
    resp_bytes               BIGINT,

    -- backend cost (NestJS interceptor → response header → nginx log)
    db_query_count           INT,
    db_total_time_ms         INT,
    cpu_time_ms              INT,
    external_call_count      INT,

    -- session
    session_id_hash          VARCHAR(64),    -- sha256(session_id), nullable
    login_present            BOOLEAN,

    -- partial request indicator (slowloris signature)
    -- offline'da hesaplanacak ama hızlı erişim için cache'liyoruz
    partial_request_flag     BOOLEAN GENERATED ALWAYS AS (
        status IN (408, 400, 444, 499)
    ) STORED,

    -- label (per-request; per-window label ayrı tabloda)
    label                    VARCHAR(32),    -- legitimate / http_flood / low_slow

    PRIMARY KEY (bucket_1s, id)
) PARTITION BY RANGE (bucket_1s);

-- Örnek partition (deneye göre genişlet):
CREATE TABLE requests_2026_w17 PARTITION OF requests
    FOR VALUES FROM ('2026-04-27 00:00:00+00') TO ('2026-05-04 00:00:00+00');

-- Critical indexes
CREATE INDEX idx_requests_src_ip_t       ON requests (src_ip, bucket_1s);
CREATE INDEX idx_requests_src_subnet24_t ON requests (src_subnet_24, bucket_1s);
CREATE INDEX idx_requests_conn           ON requests (conn_id, bucket_1s);
CREATE INDEX idx_requests_session        ON requests (session_id_hash, bucket_1s)
    WHERE session_id_hash IS NOT NULL;
CREATE INDEX idx_requests_route_t        ON requests (path_route, bucket_1s);
CREATE INDEX idx_requests_label_t        ON requests (label, bucket_1s);
CREATE INDEX idx_requests_scenario       ON requests (scenario_id, bucket_1s);

-- ============================================================
-- CONNECTIONS (Tier 1, offline derived)
-- ============================================================
-- Bu tablo nginx access log'u parse edilirken Python script tarafından
-- doldurulur. Connection bazında MIN/MAX timing'leri toplar.

CREATE TABLE connections (
    conn_id                  BIGINT PRIMARY KEY,
    scenario_id              VARCHAR(64) NOT NULL REFERENCES scenarios(scenario_id),

    src_ip                   INET NOT NULL,
    src_subnet_24            INET NOT NULL,

    t_open                   TIMESTAMPTZ NOT NULL,
    t_close                  TIMESTAMPTZ,
    duration_ms              INT,

    request_count            INT DEFAULT 0,
    keepalive_used           BOOLEAN,

    -- slow-attack indicators (KEY)
    mean_request_time_ms     INT,
    p95_request_time_ms      INT,
    max_request_time_ms      INT,
    -- header vs body recv duration tam Tier B gerektirir; nginx
    -- access log'undan tam çıkarılamaz. v1'de:
    -- header_recv_duration ≈ upstream_connect_time
    -- body_recv_duration   ≈ request_time - upstream_response_time
    -- bu yaklaşıklığın limitations'ta yazılması gerekiyor.
    mean_inbound_byte_rate   DOUBLE PRECISION,
    partial_request_count    INT DEFAULT 0,
    timeout_request_count    INT DEFAULT 0,  -- status=408

    tls_version              VARCHAR(16),
    tls_cipher               VARCHAR(64)
);

CREATE INDEX idx_connections_src_ip       ON connections (src_ip, t_open);
CREATE INDEX idx_connections_src_subnet24 ON connections (src_subnet_24, t_open);
CREATE INDEX idx_connections_scenario     ON connections (scenario_id, t_open);

-- ============================================================
-- SESSIONS (Tier 4)
-- ============================================================
CREATE TABLE sessions (
    session_id_hash          VARCHAR(64) PRIMARY KEY,
    scenario_id              VARCHAR(64) NOT NULL REFERENCES scenarios(scenario_id),

    first_seen_ip            INET,
    distinct_ips             INT DEFAULT 1,  -- session migration / sharing

    t_first_seen             TIMESTAMPTZ NOT NULL,
    t_last_seen              TIMESTAMPTZ,
    duration_ms              INT,

    request_count            INT DEFAULT 0,
    unique_endpoint_count    INT,
    navigation_depth         INT,            -- distinct route_template count
    login_present            BOOLEAN,
    think_time_p50_ms        INT
);

CREATE INDEX idx_sessions_scenario ON sessions (scenario_id, t_first_seen);

-- ============================================================
-- WINDOW LABELS (per-(key, window) ground truth)
-- ============================================================
-- Tier 2 windowed feature'ların ground truth label'ı.
-- Aggregation key tipini ayrı kolonda tutuyoruz; tek tabloda iki
-- aggregation tipi de durur.

CREATE TABLE window_labels (
    id                BIGSERIAL PRIMARY KEY,
    scenario_id       VARCHAR(64) NOT NULL REFERENCES scenarios(scenario_id),

    aggregation_type  VARCHAR(16) NOT NULL,  -- 'src_ip' | 'src_subnet_24'
    aggregation_key   TEXT NOT NULL,         -- IP adresi veya /24 string'i
    window_start      TIMESTAMPTZ NOT NULL,
    window_end        TIMESTAMPTZ NOT NULL,

    request_count_total    INT,
    request_count_attack   INT,    -- bu pencerede attacker-controlled source'tan kaç istek
    attack_ratio           DOUBLE PRECISION,  -- attack/total

    label             VARCHAR(32) NOT NULL,  -- legitimate/http_flood/low_slow
    -- tie-breaker rule: attack_ratio >= 0.20 → label = (dominant attack class)
    -- bu kural Day 16'da koddur, post-hoc değiştirilmeyecek

    UNIQUE (scenario_id, aggregation_type, aggregation_key, window_start)
);

CREATE INDEX idx_window_labels_scenario ON window_labels (scenario_id, window_start);
CREATE INDEX idx_window_labels_key      ON window_labels (aggregation_type, aggregation_key, window_start);

-- ============================================================
-- ENDPOINT COST CALIBRATION
-- ============================================================
-- Day 13'te yapılacak calibration run'ın çıktısı buraya yazılacak.
-- Daha sonra Tier 2 feature engineering bu tablodan endpoint cost vector'ünü çekecek.

CREATE TABLE endpoint_cost_profile (
    path_route               VARCHAR(255) PRIMARY KEY,
    method                   VARCHAR(8),
    sample_count             INT,
    mean_db_time_ms          DOUBLE PRECISION,
    mean_cpu_time_ms         DOUBLE PRECISION,
    mean_total_cost_ms       DOUBLE PRECISION,
    p95_total_cost_ms        DOUBLE PRECISION,
    cost_quartile            INT,  -- 1=cheapest, 4=most expensive
    calibration_scenario_id  VARCHAR(64) REFERENCES scenarios(scenario_id)
);

-- ============================================================
-- CALIBRATION BASELINES (NASA-derived)
-- ============================================================
-- Markov transition matrix, IAT empirical CDF, endpoint Zipf parameters
-- buraya pickle/jsonb olarak yazılır.

CREATE TABLE calibration_baselines (
    name                     VARCHAR(64) PRIMARY KEY,
    source_dataset           VARCHAR(64),    -- 'NASA_HTTP_1995'
    parameters               JSONB,
    fit_quality              JSONB,           -- KS / AD test stats
    created_at               TIMESTAMPTZ DEFAULT NOW()
);
