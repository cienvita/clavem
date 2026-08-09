# clavem: AI API gateway design

Status: draft, 2026-08-09

## Goal

A small, understandable AI API gateway. Clients talk to clavem with
gateway-issued keys; clavem holds the real provider credentials, forwards
requests, meters usage, prices it, and enforces budgets. Two tiers only:
the gateway binary and Postgres.

Providers at launch: Anthropic (Claude), xAI, AWS Bedrock, Azure AI
Foundry. Tool APIs: Tavily, Firecrawl.

## Non-goals

* No request/response format translation between providers. Clients use
  each provider's native wire format and SDK, pointed at clavem.
* No smart routing, retries across providers, load balancing, or model
  fallback. One request in, one upstream call out.
* No response caching.
* No multi-region or multi-instance coordination beyond what "budgets are
  approximately enforced" allows (see Budgets).

These are the things that make LiteLLM hard to reason about. Leaving them
out is the point.

## Shape

```
clients (native SDKs, base_url -> clavem)
   |
   v
+---------------------------------------------+
| clavem (single Rust binary, axum)           |
|                                             |
|  auth: virtual key lookup (cached)          |
|  route: path prefix -> provider adapter     |
|  adapter: inject real creds, forward,       |
|           stream back, sniff usage          |
|  meter: usage -> cost -> budget counters    |
|  writer: batched write-behind to Postgres   |
|  admin UI: Datastar + static Tailwind CSS   |
+---------------------------------------------+
   |
   v
Postgres (HA cluster, leader-aware connection)
```

## API surface

Pass-through with path prefixes. The prefix picks the provider adapter;
the rest of the path is forwarded verbatim.

```
POST /anthropic/v1/messages        -> api.anthropic.com/v1/messages
POST /xai/v1/chat/completions      -> api.x.ai/v1/chat/completions
POST /bedrock/model/{id}/converse  -> bedrock-runtime.{region}.amazonaws.com/...
POST /azure/{deployment-path}      -> {resource}.openai.azure.com/...
POST /tavily/search                -> api.tavily.com/search
POST /firecrawl/v2/scrape          -> api.firecrawl.dev/v2/scrape
```

Clients authenticate to clavem with a virtual key in the header slot the
native SDK already uses (`x-api-key` for Anthropic-style, `Authorization:
Bearer` for OpenAI-style). Clavem strips it, resolves it, and substitutes
the real credential. This means existing SDKs work with only a base_url
change and the virtual key in place of a real one.

Gateway-owned endpoints live under `/admin` (UI + admin API) and are never
forwarded.

## Providers

| Provider  | Upstream auth            | Usage source                          |
|-----------|--------------------------|---------------------------------------|
| Anthropic | x-api-key                | usage in JSON / message_start+delta   |
| xAI       | Bearer                   | OpenAI-shaped usage                   |
| Bedrock   | Bearer (Bedrock API key) | converse/invoke response usage        |
| Azure     | api-key                  | OpenAI-shaped usage                   |
| Tavily    | Bearer                   | per-request (credits)                 |
| Firecrawl | Bearer                   | per-request (credits)                 |

Wrinkles:

* OpenAI-shaped streaming (xAI, Azure) only reports usage when the client
  sends `stream_options: {"include_usage": true}`. The adapter rewrites
  the request body to force it on streaming requests, and drops the extra
  usage-only chunk if the client did not ask for it. This is the one place
  we touch request bodies; everything else is byte-for-byte.
* Bedrock supports plain API keys (bearer). We start there. SigV4 signing
  (for shops that refuse long-lived keys) is a later adapter option, not
  in v1. Bedrock endpoint is region-specific; region is per-provider
  config.
* Azure Foundry endpoints are per-resource; the configured upstream base
  URL is per provider instance, so you can configure several (e.g.
  `/azure-eu/`, `/azure-us/`) if needed. Same mechanism gives you two
  Anthropic orgs, etc. "Provider" in config is an instance: name, kind,
  base URL, credential ref.
* Tool APIs (Tavily, Firecrawl) have no token usage; the meter records 1
  request and prices it per-request/per-credit. Same pipeline, different
  units.

An adapter is a small trait: prepare request (auth header swap, optional
body rewrite), plus a usage sniffer for the response. The Anthropic
sniffer already exists; OpenAI-shaped is the second one; per-request is
trivial.

## Credentials

Two kinds of secret, handled differently:

* Real provider credentials: on disk (or env), one file per provider
  instance, same as today's `anthropic.key`. Not in Postgres. A database
  compromise or a stolen backup then leaks no upstream keys, and there is
  no key-encryption bootstrapping problem. Cost: adding a provider means
  touching the gateway host, not the UI. Acceptable at this scale.
* Virtual keys (gateway-issued): random 256-bit, shown once at creation,
  stored as SHA-256 in Postgres. High-entropy random keys do not need a
  slow hash. Lookup is by hash; hits are cached in memory with a short
  TTL (~30s) so Postgres is off the hot path.

## Usage and cost pipeline

Per request, the sniffer produces a usage event:

```
request_id, ts, virtual_key, provider, model,
input_tokens, output_tokens, cache_create_tokens, cache_read_tokens,
requests (1), status, latency_ms
```

Cost is computed at ingest from the price table and stored on the event
(denormalized, so later price edits do not rewrite history). Events flow
through an in-process channel to a writer task that batches inserts.
The request path never waits on Postgres.

Prices live in a table, editable from the UI:

```
price(provider_kind, model_pattern, input_usd_per_mtok,
      output_usd_per_mtok, cache_create_usd_per_mtok,
      cache_read_usd_per_mtok, per_request_usd, effective_from)
```

Model matching is exact-or-prefix (`claude-sonnet-5*`). Usage that
matches no price row is stored with cost NULL and surfaces in the UI as
"unpriced usage" instead of silently counting as zero. Price drift is
handled by humans editing the table; there is no upstream price feed.

If a client disconnects mid-stream, the sniffer finalizes with whatever
it saw; partial usage is still recorded.

## Budgets

* A budget is `(scope, period, limit_usd)`. Scope is a virtual key or
  global to start; the scope column is designed to grow user/team/org
  values later without schema surgery. Period is calendar month UTC,
  resetting at 00:00 UTC on the 1st. Fixed, not configurable.
* Enforcement is pre-flight: at request time, if the scope's
  current-period spend >= limit, reject with 402 and a JSON error before
  contacting upstream.
* Spend counters are in-memory, seeded from Postgres at startup, bumped
  as usage events are costed, and re-reconciled from Postgres
  periodically. Enforcement is therefore approximate: an in-flight
  request can overshoot the limit by its own cost. That is inherent to
  metering-after-the-fact and is fine for cost control (it is not a
  security boundary). Postgres is the single source of truth for spend;
  in-memory counters are a cache of it, never the other way round.
* This design assumes one gateway instance (or a small number sharing a
  DB, with proportionally looser enforcement). Explicit constraint, not
  an accident.

## Postgres

Schema (v1):

```
virtual_key(id, name, key_hash, enabled, created_at, note)
budget(id, key_id NULL for global, period 'month', limit_usd)
price(...)                         -- as above
usage_event(...)                   -- as above, UNIQUE(request_id)
usage_daily(day, key_id, provider, model, tokens..., cost_usd)
```

`usage_daily` is a rollup maintained by the writer (upsert per batch) so
the UI never scans `usage_event` for dashboards. `UNIQUE(request_id)`
makes writer retries idempotent.

### HA / leader awareness

Use tokio-postgres (via deadpool-postgres), not sqlx: tokio-postgres
natively supports multi-host connection strings with
`target_session_attrs=read-write`, which is exactly "know who the leader
is" without talking to Patroni/etcd:

```
host=pg1,pg2,pg3 port=5432 dbname=clavem target_session_attrs=read-write
```

On failover, existing connections die, the pool discards them, and new
connections walk the host list until they find the writable node. No
custom leader-election awareness in clavem; the driver does it.

### Failure modes

* Postgres briefly unreachable (failover window): auth continues from
  cache; budget checks use last-known counters; usage events buffer in
  the bounded in-memory queue and flush on reconnect. Requests keep
  flowing.
* Postgres down long enough to overflow the buffer: shed usage events
  oldest-first and log loudly (metered-but-unrecorded is a known,
  bounded lie), keep proxying. Fail-open on recording.
* Unknown key (cache miss and DB down): reject. Fail-closed on auth.

## Admin UI

Server-rendered HTML from the binary (maud), Datastar for interactivity,
Tailwind via the standalone CLI: a `scripts/css.sh` runs `tailwindcss -i
input.css -o assets/app.css --minify` at build time and the file is
embedded in the binary with `include_bytes!`. No node, no bundler, no
runtime asset pipeline.

Pages:

* Dashboard: spend this month by key/provider/model, live via SSE
  (Datastar's native transport; the meter already has the numbers in
  memory).
* Keys: create (show once), disable, rename.
* Budgets: set/edit limits.
* Prices: edit table, see unpriced usage.

Admin auth: single admin password (file on disk, like provider keys),
session cookie. Multi-user admin is out of scope.

## Security notes

* Virtual keys transit the network, so non-localhost deployments need
  TLS. v1: bind localhost or sit behind a reverse proxy (caddy/nginx)
  for TLS; native rustls listener is a later option.
* Request/response bodies are never persisted, only usage metadata.
* Provider creds never leave the gateway host or enter the DB.

## Implementation plan

Each phase is a working, committable state.

1. Provider registry and routing. Config file (TOML) defining provider
   instances (name, kind, base_url, key file). Path-prefix router,
   per-kind auth-header injection. Anthropic + xAI + Azure. In-memory
   totals as today.
2. Remaining adapters and sniffers. OpenAI-shaped sniffer with
   include_usage forcing; Bedrock (bearer, converse/invoke usage);
   Tavily/Firecrawl per-request metering.
3. Postgres. Schema + migrations (refinery), deadpool-postgres with
   multi-host leader-aware connstring, write-behind usage writer with
   batching, idempotent retry, daily rollups.
4. Virtual keys. Table, hashing, header swap, cache, CLI subcommand to
   mint the first key. Gateway now rejects unauthenticated requests.
5. Pricing. Price table, cost at ingest, unpriced-usage flagging, seed
   prices for launch models.
6. Budgets. Table, counters, pre-flight enforcement, 402 error shape.
7. Admin UI. Tailwind CSS generation script, maud layouts, Datastar,
   the four pages, admin login.
8. Hardening. Graceful shutdown flushing the usage queue, /metrics
   (Prometheus) for Grafana, README and deploy notes.

## Open questions

* Per-key model/provider allowlists (key X may only call Anthropic)?
  Cheap to add to virtual_key; deferred until needed.
* Bedrock SigV4: needed, or are Bedrock API keys acceptable
  organizationally?
* Retention: does usage_event need pruning (e.g. keep 13 months) or is
  growth negligible at expected volume?
