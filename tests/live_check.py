#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["httpx>=0.27", "pyyaml>=6"]
# ///
"""Live check: exercise clavem against the real providers.

Three modes:

  live_check.py                     start a throwaway gateway and check it
  live_check.py --write-config DIR  write a config plus key files, then exit
  live_check.py --url URL           check a gateway you started yourself

Credentials come from tests/live-keys.yml, which is gitignored; see
tests/live-keys.example.yml for the shape. Every request goes to the
gateway, never straight to a provider, and the client sends a placeholder
credential so a 200 proves clavem substituted the real key.

What it asserts is clavem's behaviour, not the providers' model
catalogues: an upstream 4xx that is not 401/403 still counts as a pass,
because it proves the request was routed and authenticated. Real,
billable API calls.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import yaml

REPO = Path(__file__).resolve().parent.parent
DEFAULT_KEYS = REPO / "tests" / "live-keys.yml"
EXAMPLE_KEYS = REPO / "tests" / "live-keys.example.yml"

DEFAULT_MODELS = {"anthropic": "claude-haiku-4-5", "xai": "grok-3-mini"}
PROBE = [{"role": "user", "content": "say hi in 3 words"}]


@dataclass
class Target:
    """One clavem provider instance plus the probe request to send at it."""

    name: str
    kind: str
    base_url: str
    key: str
    path: str
    body: dict
    metered: bool
    client_headers: dict = field(default_factory=dict)


def build_targets(
    keys: dict, models: dict[str, str], require_keys: bool
) -> tuple[list[Target], list[str]]:
    """Turns the credentials file into targets, reporting what it skipped.

    With require_keys false the api keys are optional: a gateway started
    elsewhere already holds them, and we only need names and paths.
    """
    targets, skipped = [], []

    def section(name: str) -> dict | None:
        entry = keys.get(name)
        if not isinstance(entry, dict):
            if entry is not None:
                skipped.append(f"{name}: expected a mapping in the keys file")
            return None
        if not entry.get("key") and require_keys:
            skipped.append(f"{name}: no key in the keys file")
            return None
        return entry

    def model_for(name: str, entry: dict) -> str:
        return models.get(name) or entry.get("model") or DEFAULT_MODELS[name]

    if (entry := section("anthropic")) is not None:
        targets.append(
            Target(
                name="anthropic",
                kind="anthropic",
                base_url="https://api.anthropic.com",
                key=entry.get("key", ""),
                path="/v1/messages",
                body={
                    "model": model_for("anthropic", entry),
                    "max_tokens": 16,
                    "messages": PROBE,
                },
                metered=True,
                # A native SDK would send its own key here; clavem must
                # replace it rather than pass it upstream.
                client_headers={"x-api-key": "placeholder"},
            )
        )

    if (entry := section("xai")) is not None:
        targets.append(
            Target(
                name="xai",
                kind="xai",
                base_url="https://api.x.ai",
                key=entry.get("key", ""),
                path="/v1/chat/completions",
                body={"model": model_for("xai", entry), "max_tokens": 16, "messages": PROBE},
                metered=False,
                client_headers={"authorization": "Bearer placeholder"},
            )
        )

    # The endpoint, deployment and api version are not secrets, but they are
    # the only way to build a valid Azure path, so they are always needed.
    if (entry := section("azure")) is not None:
        missing = [f for f in ("endpoint", "api_version", "deployment") if not entry.get(f)]
        if missing:
            skipped.append(f"azure: keys file is missing {', '.join(missing)}")
        else:
            targets.append(
                Target(
                    name="azure",
                    kind="azure",
                    base_url=entry["endpoint"].rstrip("/"),
                    key=entry.get("key", ""),
                    path=(
                        f"/openai/deployments/{entry['deployment']}/chat/completions"
                        f"?api-version={entry['api_version']}"
                    ),
                    body={
                        # Newer Azure deployments reject max_tokens.
                        "max_completion_tokens": 16,
                        "messages": PROBE,
                    },
                    metered=False,
                    client_headers={"api-key": "placeholder"},
                )
            )

    for name in keys:
        if name not in ("anthropic", "xai", "azure"):
            skipped.append(f"{name}: no adapter for this kind yet")

    return targets, skipped


def write_config(dirpath: Path, targets: list[Target], port: int, force: bool) -> Path:
    config = dirpath / "clavem.toml"
    key_files = {t.name: dirpath / f"{t.name}.key" for t in targets}
    clashes = [p for p in [config, *key_files.values()] if p.exists()]
    if clashes and not force:
        sys.exit(
            "refusing to overwrite: "
            + ", ".join(str(p) for p in clashes)
            + "\npass --force if that is what you want"
        )

    lines = ["[server]", f'listen = "127.0.0.1:{port}"', ""]
    for t in targets:
        write_secret(key_files[t.name], t.key)
        lines += [
            "[[provider]]",
            f'name = "{t.name}"',
            f'kind = "{t.kind}"',
            f'base_url = "{t.base_url}"',
            f'key_file = "{key_files[t.name].as_posix()}"',
            "",
        ]
    config.write_text("\n".join(lines), encoding="utf-8")
    return config


def write_secret(path: Path, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(value.strip() + "\n")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def find_binary(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    exe = "clavem.exe" if os.name == "nt" else "clavem"
    for profile in ("release", "debug"):
        candidate = REPO / "target" / profile / exe
        if candidate.exists():
            return candidate
    sys.exit("no clavem binary found; run cargo build or pass --binary")


def wait_ready(base: str, proc: subprocess.Popen | None, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            raise RuntimeError(f"gateway exited early with code {proc.returncode}")
        try:
            # Any response proves the listener is up; / is an unknown prefix.
            httpx.get(f"{base}/", timeout=2.0)
            return
        except httpx.HTTPError:
            time.sleep(0.2)
    raise RuntimeError(f"nothing answering on {base}")


class Results:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []

    def add(self, status: str, name: str, detail: str = "") -> None:
        self.rows.append((status, name, detail))
        print(f"{status:<4} {name}{' - ' + detail if detail else ''}", flush=True)

    def failed(self) -> int:
        return sum(1 for status, _, _ in self.rows if status == "FAIL")


def check_unknown_provider(base: str, r: Results) -> None:
    resp = httpx.post(f"{base}/openai/v1/chat/completions", json={}, timeout=10.0)
    if resp.status_code != 404:
        r.add("FAIL", "unknown prefix rejected", f"got {resp.status_code}")
        return
    kind = resp.json().get("error", {}).get("type")
    if kind != "unknown_provider":
        r.add("FAIL", "unknown prefix rejected", f"error.type={kind}")
        return
    r.add("PASS", "unknown prefix rejected", "404 unknown_provider")


def check_forward(base: str, t: Target, r: Results) -> bool:
    """Returns True if the upstream answered 200."""
    url = f"{base}/{t.name}{t.path}"
    headers = {"content-type": "application/json", **t.client_headers}
    try:
        resp = httpx.post(url, json=t.body, headers=headers, timeout=90.0)
    except httpx.HTTPError as e:
        r.add("FAIL", f"{t.name} forward", f"{type(e).__name__}: {e}")
        return False

    if resp.status_code == 404 and error_type(resp) == "unknown_provider":
        r.add("FAIL", f"{t.name} forward", f"gateway has no provider named {t.name!r}")
        return False
    if resp.status_code in (401, 403):
        r.add("FAIL", f"{t.name} forward", f"upstream rejected the credential ({resp.status_code})")
        return False
    if resp.status_code >= 500:
        r.add("FAIL", f"{t.name} forward", f"{resp.status_code} {resp.text[:200]}")
        return False
    if resp.status_code != 200:
        # Routed and authenticated, but the upstream did not like the request
        # itself (usually an unknown model id for this account).
        r.add("PASS", f"{t.name} forward", f"routed, upstream {resp.status_code}: {upstream_msg(resp)}")
        return False

    r.add("PASS", f"{t.name} forward", f"200, {summarize(resp)}")
    return True


def error_type(resp: httpx.Response) -> str:
    try:
        return resp.json().get("error", {}).get("type", "")
    except ValueError:
        return ""


def upstream_msg(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:120]
    err = body.get("error", body)
    if isinstance(err, dict):
        return str(err.get("message", err))[:160]
    return str(err)[:160]


def summarize(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return f"{len(resp.content)} bytes"
    usage = body.get("usage", {})
    model = body.get("model", "?")
    if "input_tokens" in usage:
        return f"model={model} in={usage['input_tokens']} out={usage['output_tokens']}"
    if "prompt_tokens" in usage:
        return f"model={model} prompt={usage['prompt_tokens']} completion={usage.get('completion_tokens')}"
    return f"model={model}"


def check_stream(base: str, t: Target, r: Results) -> None:
    body = dict(t.body, stream=True)
    headers = {"content-type": "application/json", **t.client_headers}
    try:
        with httpx.stream(
            "POST", f"{base}/{t.name}{t.path}", json=body, headers=headers, timeout=90.0
        ) as resp:
            if resp.status_code != 200:
                resp.read()
                r.add("PASS", f"{t.name} stream", f"routed, upstream {resp.status_code}")
                return
            events = [ln[6:].strip() for ln in resp.iter_lines() if ln.startswith("event:")]
    except httpx.HTTPError as e:
        r.add("FAIL", f"{t.name} stream", f"{type(e).__name__}: {e}")
        return

    if "message_stop" in events or "message_delta" in events:
        r.add("PASS", f"{t.name} stream", f"{len(events)} sse events")
    else:
        r.add("FAIL", f"{t.name} stream", f"unexpected events: {events[:5]}")


ANSI = re.compile(r"\x1b\[[0-9;]*m")
METER_LINE = re.compile(
    r"\[(?P<provider>[A-Za-z0-9_-]+)/(?P<model>[^\]\s]+)\] in=(?P<in>\d+) out=(?P<out>\d+)"
)


def check_metering(
    log: str | None, targets: list[Target], answered: dict[str, bool], r: Results
) -> None:
    if log is None:
        for t in targets:
            r.add("SKIP", f"{t.name} metering", "no gateway log to read; pass --log")
        return

    metered: dict[str, list[tuple[str, int, int]]] = {}
    for m in METER_LINE.finditer(ANSI.sub("", log)):
        metered.setdefault(m.group("provider"), []).append(
            (m.group("model"), int(m.group("in")), int(m.group("out")))
        )

    for t in targets:
        if not answered.get(t.name):
            r.add("SKIP", f"{t.name} metering", "no successful upstream call to meter")
            continue
        seen = metered.get(t.name, [])
        if t.metered and not seen:
            r.add("FAIL", f"{t.name} metering", "no usage recorded")
        elif t.metered:
            # An attached gateway's log may hold earlier runs too, so show
            # the most recent few and say how many there were.
            shown = ", ".join(f"{m} in={i} out={o}" for m, i, o in seen[-2:])
            extra = f" ({len(seen)} recorded)" if len(seen) > 2 else ""
            r.add("PASS", f"{t.name} metering", shown + extra)
        elif seen:
            r.add("FAIL", f"{t.name} metering", f"metered but phase 1 has no sniffer: {seen}")
        else:
            r.add("PASS", f"{t.name} metering", "not metered yet, as expected")


def run_checks(base: str, targets: list[Target], r: Results) -> dict[str, bool]:
    check_unknown_provider(base, r)
    answered = {t.name: check_forward(base, t, r) for t in targets}
    for t in targets:
        if t.kind == "anthropic":
            check_stream(base, t, r)
    return answered


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--keys", type=Path, default=DEFAULT_KEYS, help="credentials yaml")
    ap.add_argument("--url", help="check a gateway already running at this url")
    ap.add_argument("--log", type=Path, help="gateway log file, for the metering checks")
    ap.add_argument(
        "--write-config",
        type=Path,
        metavar="DIR",
        help="write a config and key files into DIR, then exit",
    )
    ap.add_argument("--force", action="store_true", help="overwrite existing config or key files")
    ap.add_argument("--port", type=int, default=4567, help="listen port for --write-config")
    ap.add_argument("--binary", help="clavem binary (default: target/release then target/debug)")
    ap.add_argument("--only", help="comma-separated provider names to check")
    ap.add_argument("--anthropic-model", help="override the model id from the keys file")
    ap.add_argument("--xai-model", help="override the model id from the keys file")
    args = ap.parse_args()

    if not args.keys.exists():
        sys.exit(
            f"no credentials file at {args.keys}\n"
            f"copy {EXAMPLE_KEYS.name} to {args.keys.name} and fill it in"
        )
    keys = yaml.safe_load(args.keys.read_text(encoding="utf-8")) or {}

    attached = bool(args.url)
    models = {"anthropic": args.anthropic_model, "xai": args.xai_model}
    targets, skipped = build_targets(keys, models, require_keys=not attached)
    if args.only:
        wanted = {n.strip() for n in args.only.split(",")}
        targets = [t for t in targets if t.name in wanted]
    if not targets:
        sys.exit("no usable providers in the credentials file")

    if args.write_config:
        args.write_config.mkdir(parents=True, exist_ok=True)
        config = write_config(args.write_config, targets, args.port, args.force)
        names = ", ".join(t.name for t in targets)
        print(f"wrote {config} with providers: {names}")
        print("\nstart the gateway:")
        print(f"  cargo run -- --config {config}")
        print("\nthen check it:")
        print(f"  uv run tests/live_check.py --url http://127.0.0.1:{args.port}")
        return 0

    r = Results()
    for note in skipped:
        r.add("SKIP", note)

    if attached:
        base = args.url.rstrip("/")
        log = None
        try:
            wait_ready(base, None, timeout=5.0)
            print(f"checking gateway at {base}, providers: "
                  f"{', '.join(t.name for t in targets)}\n", flush=True)
            answered = run_checks(base, targets, r)
            if args.log:
                log = args.log.read_text(encoding="utf-8", errors="replace")
            check_metering(log, targets, answered, r)
        except Exception as e:  # noqa: BLE001 - report and fail, never mask
            r.add("FAIL", "harness", f"{type(e).__name__}: {e}")
        failed = r.failed()
        print(f"\n{len(r.rows)} checks, {failed} failed")
        return 1 if failed else 0

    binary = find_binary(args.binary)
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    workdir = Path(tempfile.mkdtemp(prefix="clavem-live-"))
    log: str | None = None
    try:
        config = write_config(workdir, targets, port, force=True)
        logfile = workdir / "clavem.log"
        with open(logfile, "w", encoding="utf-8") as sink:
            proc = subprocess.Popen(
                [str(binary), "--config", str(config)],
                stdout=sink,
                stderr=subprocess.STDOUT,
            )
            try:
                wait_ready(base, proc, timeout=20.0)
                print(f"gateway {binary.name} on {base}, providers: "
                      f"{', '.join(t.name for t in targets)}\n", flush=True)
                answered = run_checks(base, targets, r)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()

        log = logfile.read_text(encoding="utf-8", errors="replace")
        check_metering(log, targets, answered, r)
    except Exception as e:  # noqa: BLE001 - report and fail, never mask
        r.add("FAIL", "harness", f"{type(e).__name__}: {e}")
    finally:
        # The temp dir holds real credentials, so always remove it.
        shutil.rmtree(workdir, ignore_errors=True)

    failed = r.failed()
    print(f"\n{len(r.rows)} checks, {failed} failed")
    if failed and log:
        print("\n--- gateway log ---")
        print(log.strip())
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
