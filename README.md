# clavem

An AI API gateway. Clients point their existing SDK at clavem, clavem holds
the real provider credentials, forwards the request unchanged, and records
token usage on the way back.

There is no format translation between providers: each client speaks its
provider's native wire format, so only `base_url` changes. See
[docs/design.md](docs/design.md) for the design and the phased plan.

Early. Routing and usage accounting work; virtual keys, pricing, budgets,
persistence and the admin UI do not exist yet.

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

Usage is logged per request and totalled per provider and model, printed on
graceful shutdown. Totals are in memory only and are lost on restart.

Metering currently covers the Anthropic dialect. Requests to `xai` and
`azure` are forwarded and logged but not metered, because OpenAI-shaped
streaming only reports usage when the request asks for it and the adapter
that handles that is not written yet.

Virtual keys do not exist, so clavem does not authenticate its clients.
Bind it to localhost, or put it behind a reverse proxy that does.

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
