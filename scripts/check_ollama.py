"""Smoke test: Ollama reachable, models installed, JSON round-trip works."""

from __future__ import annotations

import json
import sys

import ollama
from rich.console import Console

from chainofproof.config import Settings, load_settings

console = Console()


def installed_models(client: ollama.Client) -> set[str]:
    """Return the names of all models installed on the Ollama server."""
    return {m.model for m in client.list().models if m.model}


def json_roundtrip(client: ollama.Client, s: Settings) -> tuple[dict, float, float | None]:
    """Ask the default model for {"status":"ok"}; return (parsed, latency_s, tokens_per_s)."""
    o = s.ollama
    resp = client.chat(
        model=o.default_model,
        messages=[{"role": "user", "content": 'Reply with the JSON object {"status":"ok"} only.'}],
        format="json",
        options={"temperature": o.temperature, "num_ctx": o.num_ctx, "seed": o.seed},
    )
    latency = (resp.total_duration or 0) / 1e9
    tps = None
    if resp.eval_count and resp.eval_duration:
        tps = resp.eval_count / (resp.eval_duration / 1e9)
    return json.loads(resp.message.content), latency, tps


def main() -> int:
    """Run all checks; return a process exit code."""
    s = load_settings()
    client = ollama.Client(host=s.ollama.host)
    try:
        have = installed_models(client)
    except Exception as e:  # noqa: BLE001 - any connection failure is reported the same way
        console.print(f"[red]FAIL[/red] Ollama unreachable at {s.ollama.host}: {e}")
        return 1
    console.print(f"Ollama reachable at {s.ollama.host}; models: {sorted(have)}")
    missing = [m for m in (s.ollama.default_model, s.ollama.secondary_model) if m not in have]
    if missing:
        console.print(f"[red]FAIL[/red] missing models: {missing} (run: ollama pull <model>)")
        return 1
    try:
        out, latency, tps = json_roundtrip(client, s)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]FAIL[/red] JSON round-trip failed: {e}")
        return 1
    if out != {"status": "ok"}:
        console.print(f"[red]FAIL[/red] unexpected JSON: {out}")
        return 1
    tps_s = f"{tps:.1f}" if tps else "n/a"
    console.print(f"[green]OK[/green] {out} latency={latency:.2f}s tokens/s={tps_s}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
