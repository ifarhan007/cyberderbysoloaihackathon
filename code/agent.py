"""
CyberDerby 2026 — NovaPay SOC: Autonomous Security Incident Triage Agent

Hybrid agent: deterministic corpus cross-referencing + policy rules
+ Gemini structured reasoning + guardrails that keep every row schema-valid.

Run:
    python agent.py                 -> triage dataset/requests.csv -> ../output.csv
    python agent.py --samples       -> triage the 3 labelled samples -> evaluation/sample_predictions.csv
    python agent.py --offline       -> same, without calling Gemini (policy engine only)
    python agent.py --input X.csv --output Y.csv
Then:
    python evaluate.py
"""

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from soc.corpus import BASE, DATASET, load_corpus, load_requests   # noqa: E402
from soc.llm import GeminiClient                                    # noqa: E402
from soc.pipeline import FIELDNAMES, TriageAgent                    # noqa: E402

EVAL_DIR = HERE / "evaluation"


def load_env(path: Path = HERE / ".env"):
    """Load KEY=VALUE lines from .env into os.environ (python-dotenv if present)."""
    try:
        from dotenv import load_dotenv
        load_dotenv(path)
        return
    except ImportError:
        pass
    if path.exists():
        for line in path.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def write_csv(rows: list[dict], path: Path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES, quoting=csv.QUOTE_MINIMAL)
        w.writeheader()
        w.writerows(rows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="NovaPay SOC triage agent")
    ap.add_argument("--input", type=Path, help="incident CSV (default dataset/requests.csv)")
    ap.add_argument("--output", type=Path, help="output CSV (default ../output.csv)")
    ap.add_argument("--samples", action="store_true", help="run on dataset/sample_requests.csv")
    ap.add_argument("--offline", action="store_true", help="do not call Gemini")
    args = ap.parse_args(argv)

    load_env()
    inp = args.input or (DATASET / ("sample_requests.csv" if args.samples else "requests.csv"))
    out = args.output or (EVAL_DIR / "sample_predictions.csv" if args.samples else BASE / "output.csv")
    tag = "samples" if args.samples else "benchmark"

    print("=" * 66)
    print("  NovaPay SOC — Autonomous Triage Agent")
    print("=" * 66)
    corpus = load_corpus()
    print(f"[*] Corpus: {len(corpus.threat_ips)} threat IPs | {len(corpus.phishing_domains)} phishing domains | "
          f"{len(corpus.employees)} employees | {sum(map(len, corpus.history.values()))} history records | "
          f"{len(corpus.policy_rule_codes)} policy rules | {len(corpus.action_codes)} action codes")

    agent = TriageAgent(corpus, GeminiClient(), use_llm=not args.offline)
    print(f"[*] Mode: {agent.mode}")
    incidents = load_requests(inp)
    print(f"[*] Triaging {len(incidents)} incidents from {inp.relative_to(BASE) if inp.is_relative_to(BASE) else inp}\n")

    t0 = time.time()
    try:
        rows, traces = agent.run(incidents, progress=lambda r, t: print(
            f"  [{r['request_id']}] {r['severity']:12s} {r['incident_category']:19s} "
            f"{r['triage_decision']:22s} conf={r['confidence_score']}  engine={t['engine']}", flush=True))
    except ValueError as e:
        print(f"[!] Invalid input: {e}")
        return 2
    elapsed = time.time() - t0

    ids = [r["request_id"] for r in rows]
    assert len(ids) == len(set(ids)), "duplicate request_id in output"
    write_csv(rows, out)

    EVAL_DIR.mkdir(exist_ok=True)
    (EVAL_DIR / f"trace_{tag}.json").write_text(json.dumps(traces, indent=2, default=str))
    usage = {"run": tag, "mode": agent.mode, "incidents": len(rows), "wall_time_s": round(elapsed, 1),
             **agent.llm.usage_summary(), "calls": agent.llm.calls}
    (EVAL_DIR / f"usage_{tag}.json").write_text(json.dumps(usage, indent=2))

    overrides = sum(1 for t in traces if t["guardrails"])
    usage["engine_per_incident"] = {t["request_id"]: t["engine"] for t in traces}
    (EVAL_DIR / f"usage_{tag}.json").write_text(json.dumps(usage, indent=2))
    print(f"\n[+] Wrote {len(rows)} rows -> {out}")
    print(f"[+] Reasoning trace -> evaluation/trace_{tag}.json  |  usage -> evaluation/usage_{tag}.json")
    print(f"[*] Wall time {elapsed:.1f}s | Gemini calls {usage['http_calls']} "
          f"(ok {usage['successful_calls']}) | tokens in/out/thinking "
          f"{usage['input_tokens']}/{usage['output_tokens']}/{usage['thinking_tokens']} | "
          f"incidents with guardrail interventions: {overrides}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
