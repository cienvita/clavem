-- Requires PostgreSQL 18 for the built-in uuidv7().
--
-- Typed columns hold everything that is summed, filtered or enforced on.
-- JSONB holds documents whose shape changes over time: access policies,
-- the raw upstream usage object, and per-request metadata.

CREATE TABLE tenant (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
    name        text NOT NULL,
    enabled     boolean NOT NULL DEFAULT true,
    policy      jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(policy) = 'object'),
    metadata    jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(metadata) = 'object'),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- The id is public: it is embedded in the key string and used for lookup
-- and in logs. Only an HMAC of the secret part is stored.
CREATE TABLE virtual_key (
    id           text PRIMARY KEY CHECK (id ~ '^[a-z0-9]{12}$'),
    tenant_id    uuid NOT NULL REFERENCES tenant (id),
    name         text NOT NULL,
    secret_hmac  bytea NOT NULL CHECK (length(secret_hmac) = 32),
    hint         text NOT NULL,
    enabled      boolean NOT NULL DEFAULT true,
    policy       jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(policy) = 'object'),
    expires_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX virtual_key_tenant ON virtual_key (tenant_id);

-- Upstream credentials live in the config file, never here. A grant
-- names one by provider and credential name; many tenants can share a
-- credential and a tenant can hold several. Lowest priority wins.
CREATE TABLE credential_grant (
    tenant_id   uuid NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
    provider    text NOT NULL,
    credential  text NOT NULL,
    priority    integer NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, provider, credential)
);

-- A budget with key_id NULL applies to the whole tenant.
CREATE TABLE budget (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
    key_id        text REFERENCES virtual_key (id) ON DELETE CASCADE,
    period        text NOT NULL CHECK (period IN ('day', 'month')),
    limit_usd     numeric(20, 6) CHECK (limit_usd >= 0),
    limit_tokens  bigint CHECK (limit_tokens >= 0),
    created_at    timestamptz NOT NULL DEFAULT now(),
    CHECK (limit_usd IS NOT NULL OR limit_tokens IS NOT NULL)
);
CREATE INDEX budget_tenant ON budget (tenant_id);

-- Prices in USD per million tokens. Rows are never edited in place; a
-- price change is a new row with a later effective_from, so the price an
-- event was charged at stays recoverable through usage_event.price_id.
CREATE TABLE price (
    id                       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    provider_kind            text NOT NULL DEFAULT 'anthropic',
    model_pattern            text NOT NULL CHECK (model_pattern <> ''),
    speed                    text NOT NULL DEFAULT 'standard' CHECK (speed IN ('standard', 'fast')),
    min_prompt_tokens        bigint NOT NULL DEFAULT 0 CHECK (min_prompt_tokens >= 0),
    effective_from           timestamptz NOT NULL,
    input_usd_per_mtok       numeric(20, 6) NOT NULL CHECK (input_usd_per_mtok >= 0),
    output_usd_per_mtok      numeric(20, 6) NOT NULL CHECK (output_usd_per_mtok >= 0),
    cache_write_5m_usd_per_mtok numeric(20, 6) NOT NULL CHECK (cache_write_5m_usd_per_mtok >= 0),
    cache_write_1h_usd_per_mtok numeric(20, 6) NOT NULL CHECK (cache_write_1h_usd_per_mtok >= 0),
    cache_read_usd_per_mtok  numeric(20, 6) NOT NULL CHECK (cache_read_usd_per_mtok >= 0),
    web_search_usd_per_1k    numeric(20, 6) NOT NULL DEFAULT 0 CHECK (web_search_usd_per_1k >= 0),
    -- e.g. {"us": 1.1}: multiplier on every token price by inference_geo.
    geo_multipliers          jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(geo_multipliers) = 'object'),
    note                     text,
    created_at               timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_kind, model_pattern, speed, min_prompt_tokens, effective_from)
);

-- One row per metered upstream response. A ledger: cost is computed at
-- ingest and never recomputed. cost_usd NULL means no price matched.
CREATE TABLE usage_event (
    id                     uuid PRIMARY KEY DEFAULT uuidv7(),
    request_id             text NOT NULL UNIQUE,
    ts                     timestamptz NOT NULL,
    tenant_id              uuid NOT NULL REFERENCES tenant (id),
    key_id                 text NOT NULL REFERENCES virtual_key (id),
    provider               text NOT NULL,
    credential             text NOT NULL,
    model                  text NOT NULL,
    status                 smallint NOT NULL,
    latency_ms             integer NOT NULL,
    input_tokens           bigint NOT NULL DEFAULT 0,
    output_tokens          bigint NOT NULL DEFAULT 0,
    cache_write_5m_tokens  bigint NOT NULL DEFAULT 0,
    cache_write_1h_tokens  bigint NOT NULL DEFAULT 0,
    cache_read_tokens      bigint NOT NULL DEFAULT 0,
    cost_usd               numeric(20, 10),
    price_id               bigint REFERENCES price (id),
    usage                  jsonb NOT NULL,
    meta                   jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX usage_event_tenant_ts ON usage_event (tenant_id, ts);
CREATE INDEX usage_event_unpriced ON usage_event (ts) WHERE cost_usd IS NULL;

-- Rollup maintained by the writer in the same transaction as the events,
-- so budgets and reports never scan usage_event.
CREATE TABLE usage_daily (
    day                    date NOT NULL,
    tenant_id              uuid NOT NULL REFERENCES tenant (id),
    key_id                 text NOT NULL REFERENCES virtual_key (id),
    provider               text NOT NULL,
    model                  text NOT NULL,
    requests               bigint NOT NULL DEFAULT 0,
    unpriced_requests      bigint NOT NULL DEFAULT 0,
    input_tokens           bigint NOT NULL DEFAULT 0,
    output_tokens          bigint NOT NULL DEFAULT 0,
    cache_write_5m_tokens  bigint NOT NULL DEFAULT 0,
    cache_write_1h_tokens  bigint NOT NULL DEFAULT 0,
    cache_read_tokens      bigint NOT NULL DEFAULT 0,
    cost_usd               numeric(20, 10) NOT NULL DEFAULT 0,
    PRIMARY KEY (day, tenant_id, key_id, provider, model)
);
CREATE INDEX usage_daily_tenant_day ON usage_daily (tenant_id, day);
