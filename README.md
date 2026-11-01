# clavem

An AI API gateway. Clients point their existing SDK at clavem, clavem holds
the real provider credentials, forwards the request unchanged, and records
token usage on the way back.

There is no format translation between providers: each client speaks its
provider's native wire format, so only `base_url` changes.

Early. Routing and usage accounting work. With a Postgres database, clavem
also authenticates clients with virtual keys and short-lived tokens, prices
usage and enforces budgets, for the Anthropic dialect only. There is no admin
UI yet.

## Build

```sh
cargo build --release
```

## Configure

Copy `clavem.example.toml` to `~/.config/clavem/clavem.toml` and edit it.
Each `[[provider]]` block is one upstream instance:

```toml
[[provider]]
name = "anthropic"
kind = "anthropic"
base_url = "https://api.anthropic.com"
key_file = "~/.config/clavem/anthropic.key"
```

`name` is the path prefix clients use. `kind` selects the wire dialect and
decides which header carries the credential: `anthropic` (`x-api-key`),
`xai` (`Authorization: Bearer`) or `azure` (`api-key`). Credentials are read
from a file per instance, one line, key only.

The same kind can appear more than once under different names, which is how
you configure two Anthropic orgs or one Azure resource per region.

## Run

```sh
clavem --config ~/.config/clavem/clavem.toml
```

The first path segment picks the provider and the rest of the path is
forwarded verbatim, so `POST /anthropic/v1/messages` becomes
`POST https://api.anthropic.com/v1/messages`.

```python
from anthropic import Anthropic

# The gateway substitutes the real key, so any non-empty value works here.
client = Anthropic(api_key="proxied", base_url="http://127.0.0.1:4567/anthropic")
```

Without a `[database]` section, usage is logged per request and totalled per
provider and model, printed on graceful shutdown. Totals are in memory only
and are lost on restart.

Metering currently covers the Anthropic dialect. Requests to `xai` and
`azure` are forwarded and logged but not metered, because OpenAI-shaped
streaming only reports usage when the request asks for it and the adapter
that handles that is not written yet.

Without a database clavem does not authenticate its clients. Bind it to
localhost, or put it behind a reverse proxy that does.

## Tenants, keys and budgets

Add `[database]`, `[auth]` and `[admin]` to the config (see
`clavem.example.toml`). Migrations run at startup. From then on every
proxied request needs a clavem key, and usage is written to Postgres.

A tenant holds virtual keys, grants to one or more upstream credentials, a
policy (allowed paths, models, `max_tokens`) and day or month budgets in USD,
tokens or both. Upstream credentials stay in the config file; a provider can
have several as `[[provider.credential]]`, and grants pick between them by
name. Tenants, keys, grants, budgets and prices are managed through the API
on the `[admin]` listener; the endpoint list is at the top of `src/admin.rs`.

```sh
adm() { curl -s -H "Authorization: Bearer $(cat ~/.config/clavem/admin.token)" \
  -H 'Content-Type: application/json' "http://127.0.0.1:4569$@"; }
adm /v1/tenants -d '{"slug":"acme","name":"Acme"}'
adm /v1/tenants/acme/grants -X PUT -d '[{"provider":"anthropic","credential":"default"}]'
adm /v1/tenants/acme/keys -d '{"name":"ci"}'
```

The last call returns the key (`clv_...`) once. Clients send it as their
API key, in `x-api-key` or `Authorization: Bearer`. `POST
/_clavem/v1/token` with a key returns a `clvt_...` token valid for up to an
hour, optionally with a narrower policy, for handing to less trusted code.
A request over budget gets a 402.

## Tests

```sh
cargo test
```

`tests/live_check.py` exercises the gateway against real provider APIs and
makes billable calls, so it is a manual check rather than part of
`cargo test`. It needs credentials in `tests/live-keys.yml`; copy
`tests/live-keys.example.yml` and fill it in.

```sh
uv run tests/live_check.py                       # start a gateway and check it
uv run tests/live_check.py --url http://...      # check one already running
```

## License

MIT or Apache-2.0, at your option.
