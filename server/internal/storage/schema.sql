-- Postgres schema v2 for xray-log-analyzer.
--
-- V2 changes from v1:
--   - Extensions added: uuid-ossp, pg_stat_statements
--   - New lookup table: nodes (owned by analyzer; separate from remna_nodes)
--   - Type conversions applied consistently:
--       text columns holding a UUID          -> uuid
--       text columns holding an IP address   -> inet
--       node_id TEXT (in tables other than   -> smallint REFERENCES nodes(id)
--         the lookup itself and node_stats)
--       severity TEXT (bounded enum-like)    -> smallint
--       threat_type TEXT (bounded enum-like) -> kept as TEXT (used as PK/join key in stats tables)
--   - 4 hot time-series tables partitioned PARTITION BY RANGE (ts):
--       alerts, blacklist_matches, threat_matches, anomalies
--   - Daily partitions are managed at runtime by internal/storage/partitions/Manager.
--     Only the parent + DEFAULT partition are created here.
--   - All other tables keep existing structure with v2 types applied.
--   - IF NOT EXISTS everywhere — schema is applied on every startup.
--
-- Boolean-like INTEGER columns (resolved, sent, is_connected, etc.) are
-- kept as INTEGER for wire compatibility with existing Go code paths.
-- Task 5 may tighten them to BOOLEAN once the query layer is migrated.

-- =============================================================================
-- Extensions
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- =============================================================================
-- Lookup table: nodes (owned by analyzer, FK target for hot tables)
-- NOTE: This is DIFFERENT from remna_nodes (synced from Remnawave API).
-- Must be created before any table that references it.
-- =============================================================================

CREATE TABLE IF NOT EXISTS nodes (
    id          smallint     GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    node_id     text         NOT NULL UNIQUE,
    role        text         NOT NULL CHECK (role IN ('bridge', 'exit')),
    first_seen  timestamptz  NOT NULL DEFAULT now(),
    last_seen   timestamptz  NOT NULL DEFAULT now()
);

-- =============================================================================
-- HOT TABLES — PARTITION BY RANGE (ts)
-- =============================================================================

-- alerts
CREATE TABLE IF NOT EXISTS alerts (
    id          bigint        GENERATED ALWAYS AS IDENTITY,
    type        text          NOT NULL,
    node_id     smallint      NOT NULL REFERENCES nodes(id),
    user_email  uuid          NOT NULL,
    source_ip   inet,
    destination text,
    count       bigint        DEFAULT 0,
    message     text          NOT NULL,
    created_at  timestamptz   NOT NULL DEFAULT now(),
    sent        integer       DEFAULT 0 NOT NULL,
    ts          timestamptz   NOT NULL DEFAULT now(),
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

CREATE INDEX IF NOT EXISTS alerts_ts_brin    ON alerts USING BRIN (ts);
CREATE INDEX IF NOT EXISTS alerts_sent_idx   ON alerts (sent);
CREATE INDEX IF NOT EXISTS alerts_user_idx   ON alerts (user_email);

CREATE TABLE IF NOT EXISTS alerts_default PARTITION OF alerts DEFAULT;

-- blacklist_matches
CREATE TABLE IF NOT EXISTS blacklist_matches (
    id           bigint        GENERATED ALWAYS AS IDENTITY,
    node_id      smallint      NOT NULL REFERENCES nodes(id),
    user_email   uuid          NOT NULL,
    source_ip    inet          NOT NULL,
    destination  text          NOT NULL,
    matched_rule text          NOT NULL,
    timestamp    timestamptz   NOT NULL DEFAULT now(),
    ts           timestamptz   NOT NULL DEFAULT now(),
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

CREATE INDEX IF NOT EXISTS blacklist_matches_ts_brin   ON blacklist_matches USING BRIN (ts);
CREATE INDEX IF NOT EXISTS blacklist_matches_user_idx  ON blacklist_matches (user_email);
CREATE INDEX IF NOT EXISTS blacklist_matches_node_idx  ON blacklist_matches (node_id);

CREATE TABLE IF NOT EXISTS blacklist_matches_default PARTITION OF blacklist_matches DEFAULT;

-- threat_matches
CREATE TABLE IF NOT EXISTS threat_matches (
    id          bigint        GENERATED ALWAYS AS IDENTITY,
    user_email  uuid          NOT NULL,
    node_id     smallint      NOT NULL REFERENCES nodes(id),
    source_ip   inet          NOT NULL,
    destination text          NOT NULL,
    threat_type text          NOT NULL,
    source      text          NOT NULL,
    confidence  integer       DEFAULT 0,
    description text,
    matched_at  timestamptz   NOT NULL DEFAULT now(),
    ts          timestamptz   NOT NULL DEFAULT now(),
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

CREATE INDEX IF NOT EXISTS threat_matches_ts_brin        ON threat_matches USING BRIN (ts);
CREATE INDEX IF NOT EXISTS threat_matches_user_idx       ON threat_matches (user_email);
CREATE INDEX IF NOT EXISTS threat_matches_type_idx       ON threat_matches (threat_type);
CREATE INDEX IF NOT EXISTS threat_matches_user_type_idx  ON threat_matches (user_email, threat_type, matched_at DESC);

CREATE TABLE IF NOT EXISTS threat_matches_default PARTITION OF threat_matches DEFAULT;

-- anomalies
CREATE TABLE IF NOT EXISTS anomalies (
    id          text          NOT NULL,
    type        text          NOT NULL,
    severity    smallint      NOT NULL,
    user_email  uuid,
    description text          NOT NULL,
    details     text,                      -- JSON encoded
    detected_at timestamptz   NOT NULL DEFAULT now(),
    resolved    integer       DEFAULT 0 NOT NULL,
    ts          timestamptz   NOT NULL DEFAULT now(),
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

CREATE INDEX IF NOT EXISTS anomalies_ts_brin    ON anomalies USING BRIN (ts);
CREATE INDEX IF NOT EXISTS anomalies_user_idx   ON anomalies (user_email);
CREATE INDEX IF NOT EXISTS anomalies_type_idx   ON anomalies (type);

CREATE TABLE IF NOT EXISTS anomalies_default PARTITION OF anomalies DEFAULT;

-- =============================================================================
-- STATE TABLES (no partitioning) — v2 types applied
-- =============================================================================

-- Node and user traffic stats
-- NOTE: node_stats uses node_id as TEXT PK (it IS the lookup table equivalent;
-- kept as text for backward compat since it's not referencing the nodes FK).
CREATE TABLE IF NOT EXISTS node_stats (
    node_id          text         PRIMARY KEY,
    total_requests   bigint       DEFAULT 0,
    blacklist_hits   bigint       DEFAULT 0,
    unique_users     bigint       DEFAULT 0,
    last_seen        timestamptz,
    last_batch_time  timestamptz,
    last_batch_count bigint       DEFAULT 0
);

CREATE TABLE IF NOT EXISTS user_stats (
    id                    bigint    PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
    node_id               smallint  NOT NULL REFERENCES nodes(id),
    user_email            uuid      NOT NULL,
    total_requests        bigint    DEFAULT 0,
    blacklist_hits        bigint    DEFAULT 0,
    unique_destinations   bigint    DEFAULT 0,
    last_seen             timestamptz,
    last_ip               inet,
    last_blacklist_hit    timestamptz,
    last_blacklist_domain text,
    UNIQUE (node_id, user_email)
);

CREATE INDEX IF NOT EXISTS idx_user_stats_node            ON user_stats(node_id);
CREATE INDEX IF NOT EXISTS idx_user_stats_email           ON user_stats(user_email);
CREATE INDEX IF NOT EXISTS idx_user_stats_blacklist       ON user_stats(blacklist_hits DESC);
CREATE INDEX IF NOT EXISTS idx_user_stats_node_lastseen   ON user_stats(node_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_user_stats_requests        ON user_stats(total_requests DESC);

CREATE TABLE IF NOT EXISTS hourly_stats (
    id             bigint    PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
    node_id        smallint  NOT NULL REFERENCES nodes(id),
    hour           timestamptz NOT NULL,
    total_requests bigint    DEFAULT 0,
    blacklist_hits bigint    DEFAULT 0,
    unique_users   bigint    DEFAULT 0,
    UNIQUE (node_id, hour)
);

CREATE INDEX IF NOT EXISTS idx_hourly_stats_hour ON hourly_stats(hour DESC);

CREATE TABLE IF NOT EXISTS user_destinations (
    id            bigint    PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
    user_email    uuid      NOT NULL,
    node_id       smallint  NOT NULL REFERENCES nodes(id),
    destination   text      NOT NULL,
    request_count bigint    DEFAULT 1,
    first_seen    timestamptz,
    last_seen     timestamptz,
    UNIQUE (user_email, node_id, destination)
);

CREATE INDEX IF NOT EXISTS idx_user_dest_email ON user_destinations(user_email);
CREATE INDEX IF NOT EXISTS idx_user_dest_time  ON user_destinations(last_seen DESC);

-- =============================================================================
-- Threat aggregated stats (not partitioned — aggregated/keyed tables)
-- =============================================================================

-- Singleton row: total threat match counter
CREATE TABLE IF NOT EXISTS threat_stats_agg (
    id            integer PRIMARY KEY CHECK (id = 1),
    total_matches bigint  DEFAULT 0,
    last_updated  timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS threat_type_stats (
    threat_type text       PRIMARY KEY,
    match_count bigint     DEFAULT 0,
    last_match  timestamptz
);

CREATE TABLE IF NOT EXISTS user_threat_stats (
    user_email  uuid NOT NULL,
    threat_type text NOT NULL,
    match_count bigint DEFAULT 0,
    last_match  timestamptz,
    PRIMARY KEY (user_email, threat_type)
);

CREATE INDEX IF NOT EXISTS idx_user_threat_type  ON user_threat_stats(threat_type);
CREATE INDEX IF NOT EXISTS idx_user_threat_count ON user_threat_stats(match_count DESC);

CREATE TABLE IF NOT EXISTS user_threat_domains (
    user_email  uuid NOT NULL,
    threat_type text NOT NULL,
    domain      text NOT NULL,
    hit_count   bigint DEFAULT 1,
    last_seen   timestamptz DEFAULT now(),
    PRIMARY KEY (user_email, threat_type, domain)
);

CREATE TABLE IF NOT EXISTS threat_hourly_stats (
    hour         text   NOT NULL,            -- YYYY-MM-DDTHH
    threat_type  text   NOT NULL,
    match_count  bigint DEFAULT 0,
    unique_users bigint DEFAULT 0,
    PRIMARY KEY (hour, threat_type)
);

CREATE TABLE IF NOT EXISTS threat_hourly_users (
    hour        text NOT NULL,
    threat_type text NOT NULL,
    user_email  uuid NOT NULL,
    PRIMARY KEY (hour, threat_type, user_email)
);

CREATE TABLE IF NOT EXISTS threat_daily_stats (
    day          text   NOT NULL,            -- YYYY-MM-DD
    threat_type  text   NOT NULL,
    match_count  bigint DEFAULT 0,
    unique_users bigint DEFAULT 0,
    PRIMARY KEY (day, threat_type)
);

CREATE TABLE IF NOT EXISTS threat_daily_users (
    day         text NOT NULL,
    threat_type text NOT NULL,
    user_email  uuid NOT NULL,
    PRIMARY KEY (day, threat_type, user_email)
);

CREATE TABLE IF NOT EXISTS threat_geo_stats (
    country_code text   NOT NULL,
    country_name text   NOT NULL,
    threat_type  text   NOT NULL,
    match_count  bigint DEFAULT 0,
    unique_users bigint DEFAULT 0,
    last_match   timestamptz,
    PRIMARY KEY (country_code, threat_type)
);

CREATE INDEX IF NOT EXISTS idx_threat_geo_country ON threat_geo_stats(country_code);

-- =============================================================================
-- GeoIP / user locations / IP history
-- =============================================================================

CREATE TABLE IF NOT EXISTS user_locations (
    user_email    uuid   NOT NULL,
    country_code  text   NOT NULL,
    country_name  text   NOT NULL,
    city          text,
    latitude      double precision,
    longitude     double precision,
    last_seen     timestamptz DEFAULT now(),
    request_count bigint DEFAULT 1,
    PRIMARY KEY (user_email, country_code)
);

CREATE INDEX IF NOT EXISTS idx_user_loc_email ON user_locations(user_email);

CREATE TABLE IF NOT EXISTS user_ip_history (
    id            bigint PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
    user_email    uuid   NOT NULL,
    ip_address    inet   NOT NULL,
    node_id       smallint REFERENCES nodes(id),
    country_code  text,
    country_name  text,
    city          text,
    latitude      double precision,
    longitude     double precision,
    first_seen    timestamptz DEFAULT now(),
    last_seen     timestamptz DEFAULT now(),
    request_count bigint DEFAULT 1,
    UNIQUE (user_email, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_user_ip_email    ON user_ip_history(user_email);
CREATE INDEX IF NOT EXISTS idx_user_ip_lastseen ON user_ip_history(user_email, last_seen DESC);
-- Per-node recency lookups: filter by node_id ORDER BY last_seen DESC. Without
-- this index, Postgres falls back to seq-scan or to the user_email-leading index
-- (which doesn't match this predicate shape). On a multi-million-row hot table
-- this can dominate batch latency.
CREATE INDEX IF NOT EXISTS idx_user_ip_node_lastseen ON user_ip_history(node_id, last_seen DESC);

-- =============================================================================
-- User risk profiles / activity baselines
-- =============================================================================

CREATE TABLE IF NOT EXISTS user_activity_baseline (
    user_email         uuid PRIMARY KEY,
    avg_daily_requests double precision DEFAULT 0,
    avg_daily_threats  double precision DEFAULT 0,
    typical_hours      text,               -- JSON array
    typical_countries  text,               -- JSON array
    first_seen         timestamptz,
    updated_at         timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_risk_profiles (
    user_email       uuid PRIMARY KEY,
    risk_level       text    NOT NULL DEFAULT 'low',
    risk_score       integer NOT NULL DEFAULT 0,
    total_matches    bigint  DEFAULT 0,
    threats_by_type  text,                 -- JSON map
    unique_countries integer DEFAULT 0,
    anomaly_count    integer DEFAULT 0,
    first_seen       timestamptz,
    last_activity    timestamptz,
    days_active      integer DEFAULT 0,
    top_domains      text,                 -- JSON array
    risk_factors     text,                 -- JSON array
    trend_direction  text DEFAULT 'stable',
    updated_at       timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_risk_level ON user_risk_profiles(risk_level);
CREATE INDEX IF NOT EXISTS idx_risk_score ON user_risk_profiles(risk_score DESC);

-- =============================================================================
-- DNS analysis
-- =============================================================================

CREATE TABLE IF NOT EXISTS dns_domain_stats (
    domain         text   PRIMARY KEY,
    total_hits     bigint DEFAULT 0,
    unique_users   bigint DEFAULT 0,
    threat_types   text,                   -- JSON array
    sources        text,                   -- JSON array
    first_seen     timestamptz,
    last_seen      timestamptz,
    risk_level     text   DEFAULT 'low',
    category_hits  text                    -- JSON map category -> count
);

CREATE INDEX IF NOT EXISTS idx_dns_domain_hits ON dns_domain_stats(total_hits DESC);
CREATE INDEX IF NOT EXISTS idx_dns_domain_risk ON dns_domain_stats(risk_level);

CREATE TABLE IF NOT EXISTS dns_hourly_stats (
    hour            text   PRIMARY KEY,    -- 2006-01-02T15
    total_queries   bigint DEFAULT 0,
    blocked_queries bigint DEFAULT 0,
    unique_users    bigint DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dns_daily_stats (
    day             text   PRIMARY KEY,    -- 2006-01-02
    total_queries   bigint DEFAULT 0,
    blocked_queries bigint DEFAULT 0,
    unique_users    bigint DEFAULT 0
);

CREATE TABLE IF NOT EXISTS user_dns_stats (
    user_email      uuid   PRIMARY KEY,
    total_queries   bigint DEFAULT 0,
    blocked_queries bigint DEFAULT 0,
    top_domains     text,                  -- JSON array
    updated_at      timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_user_dns_blocked ON user_dns_stats(blocked_queries DESC);

-- =============================================================================
-- Reports
-- =============================================================================

CREATE TABLE IF NOT EXISTS reports (
    id             text PRIMARY KEY,
    type           text NOT NULL,
    format         text NOT NULL,
    title          text NOT NULL,
    description    text,
    start_date     timestamptz,
    end_date       timestamptz,
    generated_at   timestamptz DEFAULT now(),
    status         text DEFAULT 'pending',
    sections       text,                   -- JSON array
    top_threats    text,                   -- JSON array
    top_users      text,                   -- JSON array
    top_countries  text,                   -- JSON array
    summary        text                    -- JSON object
);

CREATE INDEX IF NOT EXISTS idx_reports_generated ON reports(generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_type      ON reports(type);

-- =============================================================================
-- User correlation tables for AI analysis
-- =============================================================================

CREATE TABLE IF NOT EXISTS ip_user_map (
    ip_address    inet NOT NULL,
    user_email    uuid NOT NULL,
    node_id       smallint REFERENCES nodes(id),
    first_seen    timestamptz DEFAULT now(),
    last_seen     timestamptz DEFAULT now(),
    request_count bigint DEFAULT 1,
    PRIMARY KEY (ip_address, user_email)
);

CREATE INDEX IF NOT EXISTS idx_ip_user_map_user     ON ip_user_map(user_email);
CREATE INDEX IF NOT EXISTS idx_ip_user_map_lastseen ON ip_user_map(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_ip_user_map_count    ON ip_user_map(request_count DESC);

CREATE TABLE IF NOT EXISTS hwid_user_map (
    hwid          text NOT NULL,
    user_email    uuid NOT NULL,
    platform      text,
    first_seen    timestamptz DEFAULT now(),
    last_seen     timestamptz DEFAULT now(),
    request_count bigint DEFAULT 1,
    PRIMARY KEY (hwid, user_email)
);

CREATE INDEX IF NOT EXISTS idx_hwid_user_map_user  ON hwid_user_map(user_email);
CREATE INDEX IF NOT EXISTS idx_hwid_user_map_count ON hwid_user_map(request_count DESC);

CREATE TABLE IF NOT EXISTS user_fingerprints (
    id            bigint PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
    user_email    uuid   NOT NULL,
    ip_address    inet   NOT NULL,
    hwid          text,
    user_agent    text,
    node_id       smallint REFERENCES nodes(id),
    first_seen    timestamptz DEFAULT now(),
    last_seen     timestamptz DEFAULT now(),
    session_count bigint DEFAULT 1,
    UNIQUE (user_email, ip_address, hwid)
);

CREATE INDEX IF NOT EXISTS idx_fingerprint_user ON user_fingerprints(user_email);
CREATE INDEX IF NOT EXISTS idx_fingerprint_ip   ON user_fingerprints(ip_address);
CREATE INDEX IF NOT EXISTS idx_fingerprint_hwid ON user_fingerprints(hwid);

CREATE TABLE IF NOT EXISTS user_clusters (
    cluster_id    text             NOT NULL,
    user_email    uuid             NOT NULL,
    reason        text             NOT NULL,           -- 'shared_ip' | 'shared_hwid' | 'both'
    shared_value  text             NOT NULL,
    confidence    double precision DEFAULT 0.5,
    first_linked  timestamptz      DEFAULT now(),
    last_seen     timestamptz      DEFAULT now(),
    PRIMARY KEY (cluster_id, user_email)
);

CREATE INDEX IF NOT EXISTS idx_cluster_user ON user_clusters(user_email);

CREATE TABLE IF NOT EXISTS user_ai_profile (
    user_email               uuid PRIMARY KEY,
    -- Identity
    unique_ips               bigint  DEFAULT 0,
    unique_hwids             bigint  DEFAULT 0,
    unique_fingerprints      bigint  DEFAULT 0,
    unique_countries         integer DEFAULT 0,
    unique_nodes             integer DEFAULT 0,
    -- Activity
    total_requests           bigint  DEFAULT 0,
    total_sessions           bigint  DEFAULT 0,
    avg_session_duration_sec double precision DEFAULT 0,
    -- Threats
    total_threat_matches     bigint  DEFAULT 0,
    threat_categories        text,         -- JSON map
    -- Correlation
    shared_ip_users          integer DEFAULT 0,
    shared_hwid_users        integer DEFAULT 0,
    cluster_ids              text,         -- JSON array
    -- Time
    first_seen               timestamptz,
    last_seen                timestamptz,
    active_days              integer DEFAULT 0,
    typical_hours            text,         -- JSON array
    -- Risk
    risk_score               integer DEFAULT 0,
    risk_factors             text,         -- JSON array
    -- Remnawave mirror
    remna_uuid               uuid,
    remna_status             text,
    remna_traffic_used       bigint DEFAULT 0,
    remna_traffic_limit      bigint DEFAULT 0,
    remna_expire_at          timestamptz,
    remna_hwid_devices       integer DEFAULT 0,
    remna_hwid_limit         integer DEFAULT 0,
    -- Metadata
    updated_at               timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_profile_risk   ON user_ai_profile(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_ai_profile_shared ON user_ai_profile(shared_ip_users DESC, shared_hwid_users DESC);

CREATE TABLE IF NOT EXISTS user_sessions (
    id                bigint PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
    user_email        uuid   NOT NULL,
    ip_address        inet   NOT NULL,
    hwid              text,
    node_id           smallint REFERENCES nodes(id),
    started_at        timestamptz DEFAULT now(),
    ended_at          timestamptz,
    request_count     bigint DEFAULT 0,
    bytes_transferred bigint DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_email);
CREATE INDEX IF NOT EXISTS idx_sessions_time ON user_sessions(started_at DESC);

-- =============================================================================
-- Remnawave mirror (synced from Remnawave API)
-- NOTE: remna_users.uuid is the Remnawave UUID (text PK in v1, uuid in v2).
-- =============================================================================

CREATE TABLE IF NOT EXISTS remna_users (
    uuid                    uuid PRIMARY KEY,
    id                      bigint,
    short_uuid              text,
    username                text NOT NULL,
    email                   text,
    status                  text NOT NULL,
    traffic_limit_bytes     bigint DEFAULT 0,
    used_traffic_bytes      bigint DEFAULT 0,
    lifetime_traffic_bytes  bigint DEFAULT 0,
    traffic_limit_strategy  text,
    expire_at               timestamptz,
    online_at               timestamptz,
    first_connected_at      timestamptz,
    hwid_device_limit       integer,
    hwid_device_count       integer DEFAULT 0,
    telegram_id             bigint,
    description             text,
    tag                     text,
    created_at              timestamptz,
    updated_at              timestamptz,
    synced_at               timestamptz DEFAULT now(),
    real_name               text,
    phone                   text,
    telegram_user           text,
    payment_info            text,
    plan                    text,
    us_id                   text
);

CREATE INDEX IF NOT EXISTS idx_remna_users_username ON remna_users(username);
CREATE INDEX IF NOT EXISTS idx_remna_users_email    ON remna_users(email);
CREATE INDEX IF NOT EXISTS idx_remna_users_status   ON remna_users(status);
CREATE INDEX IF NOT EXISTS idx_remna_users_online   ON remna_users(online_at DESC);
CREATE INDEX IF NOT EXISTS idx_remna_users_expire   ON remna_users(expire_at);
CREATE INDEX IF NOT EXISTS idx_remna_users_tag      ON remna_users(tag);
CREATE INDEX IF NOT EXISTS idx_remna_users_traffic  ON remna_users(used_traffic_bytes DESC);
CREATE INDEX IF NOT EXISTS idx_remna_users_id       ON remna_users(id);
CREATE INDEX IF NOT EXISTS idx_remna_users_us_id    ON remna_users(us_id);

CREATE TABLE IF NOT EXISTS remna_hwid_devices (
    id             bigint PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
    hwid           text   NOT NULL,
    user_uuid      uuid   NOT NULL,
    username       text,
    platform       text,
    os_version     text,
    device_model   text,
    app_version    text,
    first_seen_at  timestamptz DEFAULT now(),
    last_active_at timestamptz,
    synced_at      timestamptz DEFAULT now(),
    UNIQUE (hwid, user_uuid)
);

CREATE INDEX IF NOT EXISTS idx_remna_hwid_hwid   ON remna_hwid_devices(hwid);
CREATE INDEX IF NOT EXISTS idx_remna_hwid_user   ON remna_hwid_devices(user_uuid);
CREATE INDEX IF NOT EXISTS idx_remna_hwid_active ON remna_hwid_devices(last_active_at DESC);

CREATE TABLE IF NOT EXISTS remna_nodes (
    uuid             text    PRIMARY KEY,
    name             text    NOT NULL,
    address          text,
    port             integer,
    is_connected     integer DEFAULT 0 NOT NULL,
    is_disabled      integer DEFAULT 0 NOT NULL,
    is_traffic_track integer DEFAULT 0 NOT NULL,
    traffic_total    bigint  DEFAULT 0,
    traffic_used     bigint  DEFAULT 0,
    users_online     bigint  DEFAULT 0,
    country_code     text,
    synced_at        timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_remna_nodes_connected ON remna_nodes(is_connected);
CREATE INDEX IF NOT EXISTS idx_remna_nodes_country   ON remna_nodes(country_code);

-- =============================================================================
-- Online snapshots (1/min cron)
-- =============================================================================

CREATE TABLE IF NOT EXISTS online_snapshots (
    ts           timestamptz PRIMARY KEY,
    total_online bigint      NOT NULL
);

-- =============================================================================
-- AI chat sessions
-- =============================================================================

CREATE TABLE IF NOT EXISTS ai_chat_sessions (
    id           text PRIMARY KEY,
    title        text,
    created_at   timestamptz DEFAULT now(),
    updated_at   timestamptz DEFAULT now(),
    total_tokens bigint DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_chat_sessions_updated ON ai_chat_sessions(updated_at DESC);

CREATE TABLE IF NOT EXISTS ai_chat_messages (
    id          bigint PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
    session_id  text   NOT NULL REFERENCES ai_chat_sessions(id) ON DELETE CASCADE,
    role        text   NOT NULL,
    content     text   NOT NULL,
    tokens_used bigint DEFAULT 0,
    created_at  timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_session ON ai_chat_messages(session_id);
CREATE INDEX IF NOT EXISTS idx_chat_messages_time    ON ai_chat_messages(created_at);

-- =============================================================================
-- email_index: reverse lookup for SHA-1-derived user_email UUIDs that could
-- not be resolved to a Remnawave user. Allows UI to display the original raw
-- identifier for unknown synthetic IDs (e.g. "5117", "u-out").
-- =============================================================================

CREATE TABLE IF NOT EXISTS email_index (
    uuid           uuid        PRIMARY KEY,
    original_email text        NOT NULL,
    first_seen     timestamptz NOT NULL DEFAULT now()
);

-- =============================================================================
-- Seed rows
-- =============================================================================

INSERT INTO threat_stats_agg (id, total_matches) VALUES (1, 0) ON CONFLICT DO NOTHING;
