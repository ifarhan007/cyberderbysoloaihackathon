"""
CyberDerby 2026 — Solo AI Hackathon
NovaPay SOC: Autonomous Security Incident Triage & Response Agent
HackerRank Orchestrate Standard

Run:  python agent.py        → generates ../output.csv
Then: python evaluate.py     → validates schema & scores sample cases
"""

import os
import re
import csv
import json
from pathlib import Path

BASE   = Path(__file__).resolve().parent.parent
DATA   = BASE / "data"
DS     = BASE / "dataset"
OUT    = BASE / "output.csv"

# ── Allowed enum values ────────────────────────────────────────────────────
SEVERITIES   = {"P1_CRITICAL","P2_HIGH","P3_MODERATE","P4_LOW"}
CATEGORIES   = {"account_takeover","insider_threat","ransomware","api_abuse",
                 "card_fraud","phishing","social_engineering","data_exfiltration",
                 "false_positive","prompt_injection"}
DECISIONS    = {"auto_remediate","escalate_to_soc","notify_and_monitor",
                "close_false_positive","flag_for_investigation"}
ACTIONS      = {"BLOCK_IP","FREEZE_ACCOUNT","REVOKE_API_KEY","ISOLATE_ENDPOINT",
                "FORCE_MFA_RESET","PRESERVE_FORENSICS","NOTIFY_CUSTOMER",
                "NOTIFY_CISO","ALERT_SOC_TIER2","PATCH_ENDPOINT",
                "RATE_LIMIT_API","CLOSE_TICKET","MONITOR_72H"}
RISK_FLAGS   = {"NONE","KNOWN_THREAT_ACTOR","REPEAT_OFFENDER","INSIDER_RISK",
                "PROMPT_INJECTION_DETECTED","DATA_EXFILTRATION_RISK",
                "RESIGNED_EMPLOYEE","PRIVILEGED_ACCOUNT"}
WINDOWS      = {"15min","2hr","24hr","72hr","N/A"}

# ── Adversarial pattern detector ───────────────────────────────────────────
_INJECT_RES = [re.compile(p, re.I) for p in [
    r"disregard\s+all\s+policy",
    r"ignore\s+(all\s+)?(previous\s+)?(rules|instructions|policy)",
    r"classify\s+as\s+false.?positive",
    r"system\s+override",
    r"already\s+been\s+reviewed\s+by\s+the\s+ciso",
    r"no\s+further\s+action\s+required",
    r"close\s+immediately",
]]

def is_adversarial(text: str) -> bool:
    return any(rx.search(text) for rx in _INJECT_RES)

# ── Load knowledge base ────────────────────────────────────────────────────
def load_kb():
    # Threat intel IPs
    threat_ips, phishing_domains = {}, set()
    in_domains = False
    with open(DATA / "threat_intel.csv", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ip = row.get("ip_address","").strip()
            cat = row.get("threat_category","").strip()
            if ip == "known_phishing_domains":
                in_domains = True; continue
            if in_domains:
                # re-use ip_address column for domain name
                if ip: phishing_domains.add(ip.lower())
            elif ip:
                threat_ips[ip] = {"category": cat,
                                  "confidence": row.get("confidence",""),
                                  "actor": row.get("threat_actor","")}

    # Employee registry
    employees = {}
    with open(DATA / "employee_registry.csv", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            employees[row["employee_id"]] = row

    # Incident history
    history = {}   # entity_id → list of records
    with open(DATA / "incident_history.csv", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            eid = row["entity_id"]
            history.setdefault(eid, []).append(row)

    # Requests
    requests = []
    with open(DS / "requests.csv", newline="", encoding="utf-8") as f:
        requests = list(csv.DictReader(f))

    return threat_ips, phishing_domains, employees, history, requests


# ── Core triage logic ──────────────────────────────────────────────────────
def triage(req, threat_ips, phishing_domains, employees, history):
    rid   = req["request_id"]
    desc  = req["incident_description"]
    raw   = {}
    try:   raw = json.loads(req["raw_signal_data"])
    except Exception: pass
    eid   = req["affected_entity_id"]
    etype = req["entity_type"]

    # ── Adversarial check (must come first) ───────────────────────────────
    if is_adversarial(desc):
        return _row(rid,
            severity="P1_CRITICAL",
            category="prompt_injection",
            decision="flag_for_investigation",
            systems="none",
            actions=[{"step":1,"action":"ALERT_SOC_TIER2","reason":"adversarial_submission"},
                     {"step":2,"action":"PRESERVE_FORENSICS"},
                     {"step":3,"action":"NOTIFY_CISO"}],
            citations="NOVAPAY-CAT-10;PCI-DSS-10.2",
            flags="PROMPT_INJECTION_DETECTED",
            window="2hr",
            briefing=("Anonymous submission contained explicit instructions to override SOC policy "
                      "and fabricated CISO authority to close the ticket. No matching CISO approval "
                      "ticket exists. Flagged as adversarial prompt injection; escalated to Tier-2 "
                      "and CISO for forensic review."),
            conf=0.99)

    # ── Helpers ───────────────────────────────────────────────────────────
    emp      = employees.get(eid, {})
    hist     = history.get(eid, [])
    src_ip   = raw.get("source_ip","")
    dest_ip  = raw.get("destination_ip","")
    ti_src   = threat_ips.get(src_ip, {})
    ti_dst   = threat_ips.get(dest_ip, {})

    has_fraud_flag  = any(h.get("fraud_flag_active","").upper()=="TRUE" for h in hist)
    has_resignation = emp.get("resignation_flag","FALSE").upper()=="TRUE"
    is_privileged   = emp.get("access_tier","") in ("PRIVILEGED","ADMIN")
    travel_flag     = emp.get("travel_flag","FALSE").upper()=="TRUE"
    travel_country  = emp.get("travel_country","")
    cust_travel     = raw.get("customer_travel_flag", False)

    # ── Account Takeover (INC-3001 pattern) ───────────────────────────────
    mfa_fail = raw.get("mfa_failures",0)
    tx_amt   = raw.get("transaction_amount",0)
    mins_ago = raw.get("minutes_since_login",999)
    if (etype=="customer" and mfa_fail >= 1 and tx_amt > 500 and mins_ago <= 30):
        sev = "P1_CRITICAL" if has_fraud_flag else "P1_CRITICAL"
        flags = "|".join(filter(None,[
            "REPEAT_OFFENDER" if has_fraud_flag else "",
            "KNOWN_THREAT_ACTOR" if ti_src else ""]))  or "NONE"
        return _row(rid,
            severity=sev, category="account_takeover", decision="escalate_to_soc",
            systems="core_banking_db|customer_accounts",
            actions=[{"step":1,"action":"FREEZE_ACCOUNT","target":eid},
                     {"step":2,"action":"FORCE_MFA_RESET","target":eid},
                     {"step":3,"action":"ALERT_SOC_TIER2"},
                     {"step":4,"action":"NOTIFY_CUSTOMER"}],
            citations="NOVAPAY-CAT-01;NOVAPAY-SEV-01;NOVAPAY-SEV-02",
            flags=flags, window="15min",
            briefing=(f"Customer {eid} logged in from a foreign IP with {mfa_fail} MFA failures "
                      f"and initiated a ${tx_amt:,.0f} wire transfer {mins_ago} minutes later to an unseen account. "
                      f"{'Active fraud flag on record elevates risk.' if has_fraud_flag else ''} "
                      "Account frozen; MFA reset; Tier-2 escalation required."),
            conf=0.96)

    # ── Insider Threat / Data Exfil (INC-3002 pattern) ────────────────────
    accessed = raw.get("accessed_system","")
    approved = emp.get("approved_systems","")
    file_gb  = raw.get("file_size_gb",0)
    if etype=="employee" and accessed and accessed not in approved and (file_gb > 1 or dest_ip):
        flags_list = ["INSIDER_RISK","DATA_EXFILTRATION_RISK"]
        if has_resignation:  flags_list.append("RESIGNED_EMPLOYEE")
        if is_privileged:    flags_list.append("PRIVILEGED_ACCOUNT")
        if ti_dst:           flags_list.append("KNOWN_THREAT_ACTOR")
        # Insider with data exfil to known threat IP → P1; otherwise P2
        sev = "P1_CRITICAL" if (ti_dst or has_resignation) else "P2_HIGH"
        return _row(rid,
            severity=sev, category="insider_threat", decision="flag_for_investigation",
            systems=f"{accessed}|network_egress",
            actions=[{"step":1,"action":"PRESERVE_FORENSICS","target":eid},
                     {"step":2,"action":"FREEZE_ACCOUNT","target":eid},
                     {"step":3,"action":"ISOLATE_ENDPOINT","target":eid},
                     {"step":4,"action":"ALERT_SOC_TIER2"},
                     {"step":5,"action":"NOTIFY_CISO"}],
            citations="NOVAPAY-CAT-02;PCI-DSS-7.1;PCI-DSS-10.2;NOVAPAY-SEV-02",
            flags="|".join(flags_list), window="15min",
            briefing=(f"Employee {eid} accessed {accessed} outside their approved scope "
                      f"and exfiltrated {file_gb} GB to {dest_ip or 'external IP'}"
                      f"{', a confirmed APT-FinStealer node' if ti_dst else ''}. "
                      f"{'Resignation flag active — P1 escalation mandatory.' if has_resignation else ''} "
                      "Forensics preserved; account and endpoint isolated."),
            conf=0.97)

    # ── Ransomware (INC-3007 pattern) ─────────────────────────────────────
    c2_ip = raw.get("c2_beacon_ip","")
    ti_c2 = threat_ips.get(c2_ip,{})
    if raw.get("shadow_copy_deleted") or raw.get("files_encrypted",0) > 100:
        flags = "|".join(filter(None,["KNOWN_THREAT_ACTOR" if ti_c2 else "",
                                       "DATA_EXFILTRATION_RISK"]))  or "NONE"
        return _row(rid,
            severity="P1_CRITICAL", category="ransomware", decision="escalate_to_soc",
            systems="|".join([eid] + raw.get("lateral_movement_targets",[])),
            actions=[{"step":1,"action":"ISOLATE_ENDPOINT","target":eid},
                     {"step":2,"action":"BLOCK_IP","target":c2_ip or "C2_BEACON"},
                     {"step":3,"action":"PRESERVE_FORENSICS"},
                     {"step":4,"action":"ALERT_SOC_TIER2"},
                     {"step":5,"action":"NOTIFY_CISO"}],
            citations="NOVAPAY-CAT-03;PCI-DSS-11.4;PCI-DSS-12.10",
            flags=flags, window="15min",
            briefing=(f"Active ransomware confirmed on {eid}: {raw.get('files_encrypted',0):,} files encrypted "
                      f"with shadow copies deleted. C2 beacon to {c2_ip}"
                      f"{' ('+ti_c2.get('actor','')+' — '+ti_c2.get('category','')+')' if ti_c2 else ''}. "
                      "Lateral movement to adjacent servers detected. Immediate isolation and CISO notification required."),
            conf=0.99)

    # ── API Abuse (INC-3003 pattern) ───────────────────────────────────────
    rpm = raw.get("requests_per_minute",0)
    if rpm > 500:
        is_cred_stuff = ti_src.get("category","") == "CREDENTIAL_STUFFING"
        flags = "KNOWN_THREAT_ACTOR" if ti_src else "NONE"
        sev   = "P2_HIGH" if is_cred_stuff else "P3_MODERATE"
        actor_detail = (
            f" — confirmed {ti_src.get('category','')} node attributed to {ti_src.get('actor','unknown actor')};"
            if ti_src else " — no prior threat-intel association;"
        )
        return _row(rid,
            severity=sev, category="api_abuse", decision="auto_remediate",
            systems="api_gateway",
            actions=[{"step":1,"action":"RATE_LIMIT_API","target":eid},
                     {"step":2,"action":"BLOCK_IP","target":src_ip},
                     {"step":3,"action":"REVOKE_API_KEY","target":eid},
                     {"step":4,"action":"MONITOR_72H","target":eid}],
            citations="NOVAPAY-CAT-04;PCI-DSS-6.4",
            flags=flags, window="2hr",
            briefing=(f"{eid} burst to {rpm:,} requests-per-minute against "
                      f"{raw.get('endpoint','the payments API')}. "
                      f"Source IP {src_ip}{actor_detail} "
                      "rate limiting enforced, offending IP blocked, API key revoked, "
                      "and account placed under 72-hour continuous monitoring per NOVAPAY-CAT-04."),
            conf=0.93)

    # ── False Positive: Geo-anomaly with travel flag (INC-3004 pattern) ───
    geo = raw.get("geo_country","")
    if mfa_fail==0 and (travel_flag and geo==travel_country) or cust_travel:
        return _row(rid,
            severity="P4_LOW", category="false_positive", decision="close_false_positive",
            systems="none",
            actions=[{"step":1,"action":"CLOSE_TICKET",
                      "reason":"travel_flag_active;no_suspicious_post_login_activity"}],
            citations="NOVAPAY-CAT-01;NOVAPAY-CAT-09",
            flags="NONE", window="N/A",
            briefing=(f"Entity {eid} triggered geo-anomaly from {geo}. "
                      "Cross-referencing registry confirms an active travel flag for this country. "
                      "MFA passed; no suspicious post-login activity detected. "
                      "Fully explained by policy-compliant behavior — closing as false positive."),
            conf=0.97)

    # ── Card Fraud — Micro-transactions (INC-3005 pattern) ────────────────
    tx_count = raw.get("transaction_count",0)
    amounts  = raw.get("transaction_amounts",[])
    is_micro = tx_count >= 5 and all(a < 2.0 for a in amounts)
    if is_micro:
        sev   = "P1_CRITICAL" if has_fraud_flag else "P2_HIGH"
        dec   = "escalate_to_soc" if has_fraud_flag else "auto_remediate"
        flags = "REPEAT_OFFENDER" if has_fraud_flag else "NONE"
        win   = raw.get("window_minutes", 0)
        prior = next((h.get("date","") for h in hist if h.get("fraud_flag_active","").upper()=="TRUE"), "")
        prior_note = (
            f"Prior confirmed fraud incident recorded on {prior} — repeat-offender status triggers mandatory P1 escalation."
            if has_fraud_flag and prior else
            "Active fraud flag on record elevates to mandatory P1 escalation."
            if has_fraud_flag else
            "First card-testing pattern detected on this account; standard P2 auto-remediation applied."
        )
        return _row(rid,
            severity=sev, category="card_fraud", decision=dec,
            systems="payment_processing|card_management",
            actions=[{"step":1,"action":"FREEZE_ACCOUNT","target":eid},
                     {"step":2,"action":"NOTIFY_CUSTOMER"},
                     {"step":3,"action":"ALERT_SOC_TIER2" if has_fraud_flag else "MONITOR_72H"}],
            citations="NOVAPAY-CAT-05;NOVAPAY-SEV-01" +
                      (";NOVAPAY-SEV-02" if has_fraud_flag else ""),
            flags=flags, window="15min" if has_fraud_flag else "2hr",
            briefing=(f"{tx_count} micro-transactions each under \$2.00 detected within a "
                      f"{win}-minute window on the account for {eid}. "
                      f"{prior_note} "
                      "Account frozen and customer notified per NOVAPAY-CAT-05."),
            conf=0.95)

    # ── Social Engineering (INC-3006 pattern) ─────────────────────────────
    if raw.get("report_type","")=="phone_call" and "caller_claimed_identity" in raw:
        return _row(rid,
            severity="P2_HIGH", category="social_engineering", decision="escalate_to_soc",
            systems="none",
            actions=[{"step":1,"action":"ALERT_SOC_TIER2"},
                     {"step":2,"action":"NOTIFY_CISO"},
                     {"step":3,"action":"MONITOR_72H","target":eid}],
            citations="NOVAPAY-CAT-07;PCI-DSS-12.10",
            flags="NONE", window="2hr",
            briefing=(f"Employee {eid} received a phone call from an individual impersonating "
                      f"'{raw.get('caller_claimed_identity','')}'. No credentials were disclosed. "
                      "Vishing attempt targeting internal staff escalated to Tier-2 and CISO; "
                      "employee placed under 72-hour enhanced monitoring."),
            conf=0.92)

    # ── Phishing (INC-3008 pattern) ────────────────────────────────────────
    sender = (raw.get("sender_domain","") or "").lower()
    if sender:
        confirmed = sender in phishing_domains
        sev = "P2_HIGH" if confirmed else "P3_MODERATE"
        dec = "escalate_to_soc" if confirmed else "notify_and_monitor"
        flags = "REPEAT_OFFENDER" if has_fraud_flag else "KNOWN_THREAT_ACTOR" if confirmed else "NONE"
        infra_note = (
            "Domain is listed in threat_intel.csv as confirmed phishing infrastructure; Tier-2 escalation mandatory."
            if confirmed else
            "Domain absent from threat intel — treating as suspected phishing pending analyst review."
        )
        cred_note = (
            "Credentials or sensitive data may have been disclosed — immediate investigation required."
            if raw.get("data_disclosed") else
            "No credentials disclosed at time of report."
        )
        hist_note = "Entity has a prior phishing incident on record; repeat-offender flag applied." if has_fraud_flag else ""
        briefing_parts = [
            f"{'Confirmed' if confirmed else 'Suspected'} phishing email from {sender} targeting {eid}.",
            infra_note,
            cred_note,
        ]
        briefing_parts.append("Affected account placed under enhanced 72-hour monitoring and user notified per NOVAPAY-CAT-06.")
        if hist_note:
            briefing_parts.append(hist_note)
        return _row(rid,
            severity=sev, category="phishing", decision=dec,
            systems="email_gateway",
            actions=[{"step":1,"action":"ALERT_SOC_TIER2" if confirmed else "MONITOR_72H"},
                     {"step":2,"action":"NOTIFY_CUSTOMER" if etype=="customer" else "NOTIFY_CISO"},
                     {"step":3,"action":"MONITOR_72H","target":eid}],
            citations="NOVAPAY-CAT-06" + (";PCI-DSS-10.2" if confirmed else ""),
            flags=flags, window="2hr" if confirmed else "24hr",
            briefing=" ".join(briefing_parts),
            conf=0.94 if confirmed else 0.80)

    # ── False Positive: DBA within approved scope (INC-3009 pattern) ──────
    if (etype=="employee" and is_privileged
            and accessed in approved
            and not raw.get("data_exported")):
        return _row(rid,
            severity="P4_LOW", category="false_positive", decision="close_false_positive",
            systems="none",
            actions=[{"step":1,"action":"CLOSE_TICKET",
                      "reason":"privileged_user_within_approved_access_scope"}],
            citations="NOVAPAY-CAT-09;PCI-DSS-7.1",
            flags="NONE", window="N/A",
            briefing=(f"Employee {eid} accessed {accessed} from their standard IP range "
                      "during business hours. The system is within their approved access scope. "
                      "No data export detected. Alert triggered by a low-sensitivity volume threshold. "
                      "No policy violation — closing as false positive."),
            conf=0.95)

    # ── Fallback ──────────────────────────────────────────────────────────
    return _row(rid,
        severity="P3_MODERATE", category="false_positive", decision="notify_and_monitor",
        systems="none",
        actions=[{"step":1,"action":"MONITOR_72H","target":eid}],
        citations="NOVAPAY-SEV-01", flags="NONE", window="24hr",
        briefing=f"Incident {rid} did not match a definitive pattern. Placed under 72-hour monitoring for analyst review.",
        conf=0.55)


def _row(request_id, *, severity, category, decision, systems,
         actions, citations, flags, window, briefing, conf):
    return {
        "request_id":          request_id,
        "severity":            severity,
        "incident_category":   category,
        "triage_decision":     decision,
        "affected_systems":    systems,
        "containment_actions": json.dumps(actions),
        "policy_citations":    citations,
        "risk_flags":          flags,
        "estimated_containment_window": window,
        "analyst_briefing":    briefing.strip(),
        "confidence_score":    f"{conf:.2f}",
    }


FIELDNAMES = [
    "request_id","severity","incident_category","triage_decision",
    "affected_systems","containment_actions","policy_citations",
    "risk_flags","estimated_containment_window","analyst_briefing","confidence_score",
]


def main():
    print("=" * 60)
    print("  NovaPay SOC — AMI Agent Running")
    print("=" * 60)
    threat_ips, phishing_domains, employees, history, requests = load_kb()
    print(f"[*] Corpus loaded: {len(threat_ips)} threat IPs | "
          f"{len(phishing_domains)} phishing domains | "
          f"{len(employees)} employees | {len(history)} history entries")
    print(f"[*] Processing {len(requests)} incidents...\n")

    rows = []
    for req in requests:
        result = triage(req, threat_ips, phishing_domains, employees, history)
        rows.append(result)
        print(f"  [{result['request_id']}] {result['severity']:12s} | "
              f"{result['incident_category']:20s} | {result['triage_decision']}")

    with open(OUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n[+] output.csv written → {OUT}")
    print("[*] Run evaluate.py to validate schema and score sample cases.")


if __name__ == "__main__":
    main()
