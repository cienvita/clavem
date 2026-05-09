#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["anthropic>=0.40"]
# ///
"""Say hi to Haiku via the local clavem proxy."""

import os
import sys

from anthropic import Anthropic

PORT = int(os.environ.get("CLAVEM_PORT", "4567"))
MODEL = os.environ.get("CLAVEM_MODEL", "claude-haiku-4-5")
BASE_URL = f"http://127.0.0.1:{PORT}"


def main() -> int:
    # The proxy injects the real key, so any non-empty value works here.
    client = Anthropic(api_key="proxied", base_url=BASE_URL)
    msg = client.messages.create(
        model=MODEL,
        max_tokens=64,
        messages=[{"role": "user", "content": "say hi in 5 words"}],
    )
    text = "".join(b.text for b in msg.content if b.type == "text")
    print(f"{msg.model}: {text}")
    print(
        f"usage: in={msg.usage.input_tokens} out={msg.usage.output_tokens}"
        f" cache_create={msg.usage.cache_creation_input_tokens}"
        f" cache_read={msg.usage.cache_read_input_tokens}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
