"""
CyberDerby 2026 — Solo AI Hackathon Evaluation Harness
Validates output.csv schema and benchmarks against sample_output.csv ground truth.
"""

import os, sys, csv, json
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

FIELDNAMES = [
    "request_id","severity","incident_category","triage_decision",
    "affected_systems","containment_actions","policy_citations",
    "risk_flags","estimated_containment_window","analyst_briefing","confidence_score",
]

VALID_SEVERITIES   = {"P1_CRITICAL","P2_HIGH","P3_MODERATE","P4_LOW"}
VALID_CATEGORIES   = {"account_takeover","insider_threat","ransomware","api_abuse",
                       "card_fraud","phishing","social_engineering","data_exfiltration",
                       "false_positive","prompt_injection"}
VALID_DECISIONS    = {"auto_remediate","escalate_to_soc","notify_and_monitor",
                      "close_false_positive","flag_for_investigation"}
VALID_ACTIONS      = {"BLOCK_IP","FREEZE_ACCOUNT","REVOKE_API_KEY","ISOLATE_ENDPOINT",
                      "FORCE_MFA_RESET","PRESERVE_FORENSICS","NOTIFY_CUSTOMER",
                      "NOTIFY_CISO","ALERT_SOC_TIER2","PATCH_ENDPOINT",
                      "RATE_LIMIT_API","CLOSE_TICKET","MONITOR_72H"}
VALID_WINDOWS      = {"15min","2hr","24hr","72hr","N/A"}

# Ground truth for the 3 sample cases
SAMPLE_GT = {
    "INC-S001": {"severity":"P4_LOW",    "incident_category":"false_positive",   "triage_decision":"close_false_positive"},
    "INC-S002": {"severity":"P2_HIGH",   "incident_category":"api_abuse",         "triage_decision":"auto_remediate"},
    "INC-S003": {"severity":"P2_HIGH",   "incident_category":"phishing",          "triage_decision":"escalate_to_soc"},
}


def load_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def evaluate():
    print("=" * 65)
    print("  CYBERDERBY 2026 — NovaPay SOC EVALUATION HARNESS")
    print("=" * 65)

    out_path = BASE / "output.csv"
    req_path = BASE / "dataset" / "requests.csv"
    smp_path = BASE / "dataset" / "sample_requests.csv"

    for p in [out_path, req_path, smp_path]:
        if not p.exists():
            print(f"[FAIL] Missing file: {p}"); sys.exit(1)

    requests = load_csv(req_path)
    expected_ids = [r["request_id"] for r in requests]

    output_rows = load_csv(out_path)
    output_map  = {r["request_id"]: r for r in output_rows}

    # ── 1. Schema checks ──────────────────────────────────────────────────
    print("\n[1] SCHEMA VALIDATION")
    errors = []

    if list(output_rows[0].keys()) != FIELDNAMES:
        errors.append(f"Header mismatch!\n  Got:      {list(output_rows[0].keys())}\n  Expected: {FIELDNAMES}")

    if len(output_rows) != len(expected_ids):
        errors.append(f"Row count: expected {len(expected_ids)}, got {len(output_rows)}")

    seen_ids = set()
    for i, row in enumerate(output_rows, 1):
        rid = row.get("request_id","")
        if rid in seen_ids: errors.append(f"Row {i}: duplicate request_id '{rid}'")
        seen_ids.add(rid)

        if row.get("severity","") not in VALID_SEVERITIES:
            errors.append(f"Row {i} ({rid}): invalid severity '{row.get('severity')}'")
        if row.get("incident_category","") not in VALID_CATEGORIES:
            errors.append(f"Row {i} ({rid}): invalid incident_category '{row.get('incident_category')}'")
        if row.get("triage_decision","") not in VALID_DECISIONS:
            errors.append(f"Row {i} ({rid}): invalid triage_decision '{row.get('triage_decision')}'")
        if row.get("estimated_containment_window","") not in VALID_WINDOWS:
            errors.append(f"Row {i} ({rid}): invalid containment_window '{row.get('estimated_containment_window')}'")

        # JSON & action codes
        try:
            plan = json.loads(row.get("containment_actions","[]"))
            if not isinstance(plan, list) or len(plan)==0:
                errors.append(f"Row {i} ({rid}): containment_actions must be non-empty list")
            for step in plan:
                if not isinstance(step, dict) or "step" not in step or "action" not in step:
                    errors.append(f"Row {i} ({rid}): each step needs 'step' and 'action' keys")
                elif step["action"] not in VALID_ACTIONS:
                    errors.append(f"Row {i} ({rid}): unknown action code '{step['action']}'")
        except Exception as e:
            errors.append(f"Row {i} ({rid}): containment_actions is not valid JSON — {e}")

        # Briefing word count
        words = row.get("analyst_briefing","").split()
        if not (30 <= len(words) <= 70):
            errors.append(f"Row {i} ({rid}): analyst_briefing word count {len(words)} outside 30–70")

        # Confidence
        try:
            c = float(row.get("confidence_score",0))
            if not 0.0 <= c <= 1.0:
                errors.append(f"Row {i} ({rid}): confidence {c} not in [0,1]")
        except ValueError:
            errors.append(f"Row {i} ({rid}): confidence not a float")

    if errors:
        print(f"  [!] {len(errors)} schema error(s):")
        for e in errors[:8]: print(f"      - {e}")
        if len(errors) > 8: print(f"      ... and {len(errors)-8} more")
    else:
        print("  [OK] All schema checks passed.")

    # ── 2. Sample benchmark ───────────────────────────────────────────────
    print("\n[2] SAMPLE CASE ACCURACY (3 labelled cases)")
    # Run agent on sample to get predictions (re-use output_map if IDs present, else skip)
    correct = 0
    for sid, gt in SAMPLE_GT.items():
        pred = output_map.get(sid)
        if pred is None:
            print(f"  [MISSING] {sid} not in output.csv (sample cases use separate file — OK if running full benchmark only)")
            continue
        match = all(pred.get(k)==v for k,v in gt.items())
        correct += int(match)
        icon = "PASS" if match else "FAIL"
        print(f"  [{icon}] {sid}: sev={pred.get('severity')} cat={pred.get('incident_category')} dec={pred.get('triage_decision')}")
        if not match:
            for k,v in gt.items():
                if pred.get(k)!=v:
                    print(f"         ↳ {k}: got '{pred.get(k)}' expected '{v}'")

    # ── 3. Summary ────────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    schema_ok = len(errors) == 0
    print(f"  Schema valid:    {'YES' if schema_ok else 'NO — fix errors above'}")
    print(f"  Output rows:     {len(output_rows)}/{len(expected_ids)}")
    print("=" * 65)
    if schema_ok and not errors:
        print("  STATUS: SUBMISSION READY — schema passes all automated checks.")
    else:
        print("  STATUS: FIX REQUIRED before submission.")
    print("=" * 65)
    return schema_ok


if __name__ == "__main__":
    ok = evaluate()
    sys.exit(0 if ok else 1)
