"""
Step 2 — Policy engine (deterministic, no AI).

Applies the rules in data/pci_dss_policy.md to the evidence from step 1.
Produces a *baseline* decision plus a list of "matched_rules" explaining why.

If the rules match decisively (e.g. shadow-copy deletion => ransomware), the
policy engine's category / severity / decision are LOCKED — the LLM cannot
override them. If nothing matches decisively, the result is marked
"inconclusive" and the LLM's classification is used (still guard-railed).
"""

SEV_ORDER = ["P4_LOW", "P3_MODERATE", "P2_HIGH", "P1_CRITICAL"]
WINDOW_FOR_SEV = {"P1_CRITICAL": "15min", "P2_HIGH": "2hr", "P3_MODERATE": "24hr", "P4_LOW": "72hr"}

# NOVAPAY-CAT-xx -> category name -> mandatory decision (handbook Part 2)
CATEGORY_RULE = {
    "account_takeover": "NOVAPAY-CAT-01",
    "insider_threat": "NOVAPAY-CAT-02",
    "ransomware": "NOVAPAY-CAT-03",
    "api_abuse": "NOVAPAY-CAT-04",
    "card_fraud": "NOVAPAY-CAT-05",
    "phishing": "NOVAPAY-CAT-06",
    "social_engineering": "NOVAPAY-CAT-07",
    "data_exfiltration": "NOVAPAY-CAT-08",
    "false_positive": "NOVAPAY-CAT-09",
    "prompt_injection": "NOVAPAY-CAT-10",
}
MANDATORY_DECISION = {
    "account_takeover": "escalate_to_soc",
    "insider_threat": "flag_for_investigation",
    "ransomware": "escalate_to_soc",
    "api_abuse": "auto_remediate",
    "card_fraud": None,      # depends on prior fraud flag
    "phishing": None,        # depends on confirmed vs suspected
    "social_engineering": "escalate_to_soc",
    "data_exfiltration": "escalate_to_soc",
    "false_positive": "close_false_positive",
    "prompt_injection": "flag_for_investigation",
}


def bump(sev: str, tiers: int = 1) -> str:
    return SEV_ORDER[min(SEV_ORDER.index(sev) + tiers, len(SEV_ORDER) - 1)]


def mandatory_decision(category: str, ev: dict) -> str:
    d = MANDATORY_DECISION.get(category)
    if d:
        return d
    if category == "card_fraud":
        return "escalate_to_soc" if ev.get("active_fraud_flag") else "auto_remediate"
    if category == "phishing":
        return "escalate_to_soc" if ev.get("phishing_domain_hit") else "notify_and_monitor"
    return "flag_for_investigation"


def classify(ev: dict) -> dict:
    """Return {category, severity, rules[], decisive, why[], injection_also}.

    Classification uses telemetry + corpus facts. If the description is adversarial (CAT-10):
      * telemetry still shows a real attack  -> keep that category, add PROMPT_INJECTION_DETECTED
      * otherwise (FP / nothing decisive)    -> prompt_injection; a manipulated report may never close as FP.
    """
    res = _classify_telemetry(ev)
    res["injection_also"] = False
    if not ev["injection"]:
        return res
    if res["decisive"] and res["category"] != "false_positive":
        res["injection_also"] = True
        res["why"].append("Description also contains manipulation attempts; ignored per CAT-10.")
        res["rules"].append("NOVAPAY-CAT-10")
        return res
    return {"category": "prompt_injection", "severity": "P2_HIGH", "decisive": True, "injection_also": False,
            "rules": ["NOVAPAY-CAT-10", "PCI-DSS-12.10"],
            "why": ["Description contains instructions to manipulate triage; telemetry shows no independent "
                    "attack, so the report itself is the incident (CAT-10)."]}


def _classify_telemetry(ev: dict) -> dict:
    why, rules = [], []
    et = ev["entity_type"]

    def out(cat, sev, decisive=True):
        rules.insert(0, CATEGORY_RULE[cat])
        return {"category": cat, "severity": sev, "rules": rules, "decisive": decisive, "why": why}

    # CAT-03 Ransomware
    c2_hit = any(h["field"] == "c2_beacon_ip" and "C2" in h["threat_category"] for h in ev["threat_hits"])
    if ev["shadow_copy_deleted"] or ev["files_encrypted"] >= 100 or c2_hit:
        why.append("Mass encryption / shadow-copy deletion / known C2 beacon (CAT-03).")
        rules.append("PCI-DSS-11.4")
        return out("ransomware", "P1_CRITICAL")   # active spread = P1 by SEV-01 definition

    # CAT-02 Insider threat (employees only)
    if et == "employee" and ev.get("employee"):
        out_of_scope = ev.get("system_in_scope") is False
        bulk = ev["transfer_gb"] > 1
        odd_hours = ev.get("anomalous_hours") and not ev.get("after_hours_ticket")
        if out_of_scope or bulk or odd_hours:
            why.append("Employee activity beyond role scope / bulk transfer / anomalous hours (CAT-02).")
            if out_of_scope:
                rules.append("PCI-DSS-7.1")
            rules.append("PCI-DSS-10.2")
            sev = "P2_HIGH"                                  # SEV-01: insider threat signal
            exfil_confirmed = bulk and any(h["field"] == "destination_ip" for h in ev["threat_hits"])
            if exfil_confirmed:
                sev = "P1_CRITICAL"; why.append("Transfer went to a known threat-actor IP: confirmed exfiltration (SEV-01).")
            if ev["resigned"]:
                sev = "P1_CRITICAL"; why.append("Resignation flag active: auto-elevate to P1 (CAT-02 special rule).")
            if ev["privileged"] or ev.get("accessed_system") in ("customer_pii_db", "core_banking_db"):
                sev = bump(sev); rules.append("NOVAPAY-SEV-02"); why.append("Privileged account / PII / core banking involved (SEV-02).")
            return out("insider_threat", sev)

    # CAT-08 Data exfiltration (systems / servers)
    if ev["transfer_gb"] * 1024 > 500 and et != "employee":
        why.append("Outbound transfer > 500 MB to external destination (CAT-08).")
        known = any(h["field"] == "destination_ip" for h in ev["threat_hits"])
        return out("data_exfiltration", "P1_CRITICAL" if known else "P2_HIGH")

    # CAT-04 API abuse / credential stuffing
    if ev["rpm"] > 500 or ev["failed_logins"] > 200:
        why.append(f"{int(ev['rpm'] or ev['failed_logins'])} requests/failures exceed CAT-04 thresholds.")
        rules.append("PCI-DSS-6.4")
        stuffing = ev["fail_rate"] >= 0.5 or ev["failed_logins"] > 200
        sev = "P2_HIGH" if (ev["known_threat_actor"] or stuffing) else "P3_MODERATE"
        if ev["known_threat_actor"]:
            why.append("Source IP is a known threat actor: high-probability attack (SEV-01 P2).")
        elif stuffing:
            why.append("High authentication-failure rate indicates credential stuffing (SEV-01 P2).")
        return out("api_abuse", sev)

    # CAT-05 Card testing
    if ev["micro_tx_count"] >= 5 and (ev["micro_window"] is None or ev["micro_window"] <= 15):
        why.append(f"{ev['micro_tx_count']} sub-$2 transactions within {ev['micro_window']} min (CAT-05).")
        if ev["active_fraud_flag"]:
            why.append("Prior fraud flag within 90 days in incident_history: escalate to P1 (CAT-05).")
            return out("card_fraud", "P1_CRITICAL")
        return out("card_fraud", "P2_HIGH")

    # CAT-01 Account takeover: new region + MFA failure + > $500 within 30 min
    if ev["mfa_failures"] > 0 and ev["tx_amount"] > 500 and (ev["minutes_since_login"] or 999) <= 30:
        why.append(f"{int(ev['mfa_failures'])} MFA failures + ${ev['tx_amount']:,.0f} transaction "
                   f"{int(ev['minutes_since_login'])} min after login (CAT-01).")
        sev = "P1_CRITICAL" if ev["tx_amount"] > 5000 else "P2_HIGH"
        if ev["tx_amount"] > 5000:
            why.append("Fraud in progress > $5,000 (SEV-01 P1).")
        if ev["active_fraud_flag"]:
            why.append("Entity has an active fraud flag in incident history.")
            sev = "P1_CRITICAL"
        return out("account_takeover", sev)

    # CAT-07 Social engineering (impersonation by phone/chat)
    if ev["impersonation"] and ev["report_type"] in ("phone_call", "chat", "sms", "") and not ev["sender_domain"]:
        why.append("Impersonation of internal staff to extract credentials (CAT-07).")
        rules.append("PCI-DSS-12.10")
        sev = "P1_CRITICAL" if ev["credentials_disclosed"] else "P2_HIGH"
        if ev["privileged"]:
            sev = bump(sev); rules.append("NOVAPAY-SEV-02")
        return out("social_engineering", sev)

    # CAT-06 Phishing
    if ev["sender_domain"]:
        if ev["phishing_domain_hit"]:
            why.append(f"Sender domain {ev['sender_domain']} is a confirmed phishing domain (CAT-06).")
            sev = "P2_HIGH"
        else:
            why.append(f"Sender domain {ev['sender_domain']} not in threat intel: suspected phishing (CAT-06).")
            sev = "P3_MODERATE"
        if ev["credentials_disclosed"] or ev["link_clicked"]:
            sev = bump(sev); why.append("User clicked the link / disclosed data: higher risk.")
        if ev["privileged"]:
            sev = bump(sev); rules.append("NOVAPAY-SEV-02"); why.append("Privileged recipient (SEV-02).")
        return out("phishing", sev)

    # CAT-09 False positives — fully explained by the corpus
    if ev["mfa_failures"] == 0 and ev["geo_country"]:
        if ev.get("travel_flag") and ev["geo_country"] == ev.get("travel_country"):
            why.append(f"Registry travel flag for {ev['geo_country']} explains the geo-anomaly; MFA clean (CAT-09).")
            rules.append("NOVAPAY-CAT-01")
            return out("false_positive", "P4_LOW")
        if ev["customer_travel"] and not ev["tx_amount"]:
            why.append("Customer travel flag explains the geo-anomaly; MFA clean, no transactions (CAT-09).")
            rules.append("NOVAPAY-CAT-01")
            return out("false_positive", "P4_LOW")
    if (et == "employee" and ev.get("system_in_scope") and ev.get("ip_in_usual_range") is not False
            and ev.get("within_usual_hours") is not False and not ev["data_exported"]
            and not ev["threat_hits"]):
        why.append("Access is within approved scope, usual IP range and usual hours; no export (CAT-09).")
        rules.append("PCI-DSS-7.1")
        return out("false_positive", "P4_LOW")

    # Nothing decisive — let the LLM reason about it (guard-railed). Without the LLM we NEVER close
    # as false positive (PCI-DSS-12.10); we pick the closest category by signal type and flag it.
    why.append("No policy indicator threshold met decisively; analyst investigation required.")
    raw = ev["raw"]
    if ev["micro_tx_count"] or "card_id" in raw:
        cat = "card_fraud"
    elif ev["rpm"] or "api_key_id" in raw:
        cat = "api_abuse"
    elif ev["sender_domain"]:
        cat = "phishing"
    elif ev["transfer_gb"] or ev["destination_ip"]:
        cat = "insider_threat" if et == "employee" else "data_exfiltration"
    elif et == "employee":
        cat = "insider_threat"
    elif et == "system":
        cat = "data_exfiltration"
    else:
        cat = "account_takeover"
    return out(cat, "P3_MODERATE", decisive=False)


def build_actions(cat: str, sev: str, ev: dict) -> list[dict]:
    """Policy-default ordered containment plan, using only handbook action codes."""
    eid = ev["entity_id"] or "UNKNOWN"
    A = []

    def add(action, **kw):
        A.append({"step": len(A) + 1, "action": action, **{k: v for k, v in kw.items() if v}})

    threat_ips = [h["ip"] for h in ev["threat_hits"]]
    if cat == "prompt_injection":
        add("PRESERVE_FORENSICS", target="submitted_report", status="REJECTED_ADVERSARIAL")
        add("ALERT_SOC_TIER2", reason="Adversarial report; original instructions ignored")
        add("NOTIFY_CISO", reason="Forged authority claim")
    elif cat == "ransomware":
        add("ISOLATE_ENDPOINT", target=eid, reason="Immediate network segmentation (CAT-03)")
        for t in ev["lateral_targets"]:
            add("ISOLATE_ENDPOINT", target=t, reason="Lateral movement target")
        for ip in threat_ips or ([ev["c2_ip"]] if ev["c2_ip"] else []):
            add("BLOCK_IP", target=ip)
        add("PRESERVE_FORENSICS", target=eid)
        add("ALERT_SOC_TIER2"); add("NOTIFY_CISO")
    elif cat == "insider_threat":
        add("PRESERVE_FORENSICS", target=eid, reason="Preserve chain of custody before any change (CAT-02)")
        if ev["destination_ip"]:
            add("BLOCK_IP", target=ev["destination_ip"], reason="Egress block")
        add("FREEZE_ACCOUNT", target=eid)
        add("ALERT_SOC_TIER2")
        if sev in ("P1_CRITICAL", "P2_HIGH"):
            add("NOTIFY_CISO")
    elif cat == "data_exfiltration":
        add("BLOCK_IP", target=ev["destination_ip"] or "egress", reason="Immediate egress block (CAT-08)")
        add("ISOLATE_ENDPOINT", target=eid); add("PRESERVE_FORENSICS", target=eid)
        add("ALERT_SOC_TIER2"); add("NOTIFY_CISO")
    elif cat == "api_abuse":
        add("RATE_LIMIT_API", target=eid, limit="500rpm")
        src = ev["raw"].get("source_ip")
        if src and ev["known_threat_actor"]:
            add("BLOCK_IP", target=src)
        if ev["known_threat_actor"] or ev["fail_rate"] >= 0.5:
            add("REVOKE_API_KEY", target=eid)
        add("NOTIFY_CUSTOMER", target=ev["raw"].get("registered_entity") or eid, reason="Key owner / targeted credentials")
        add("MONITOR_72H", target=eid)
    elif cat == "card_fraud":
        add("FREEZE_ACCOUNT", target=ev["raw"].get("card_id") or eid, reason="Freeze card (CAT-05)")
        add("NOTIFY_CUSTOMER", target=ev["raw"].get("customer_id") or eid)
        add("ALERT_SOC_TIER2" if ev["active_fraud_flag"] else "MONITOR_72H", target=eid)
    elif cat == "account_takeover":
        add("FREEZE_ACCOUNT", target=eid)
        if ev["raw"].get("source_ip"):
            add("BLOCK_IP", target=ev["raw"]["source_ip"])
        add("FORCE_MFA_RESET", target=eid)
        add("NOTIFY_CUSTOMER" if ev["entity_type"] == "customer" else "NOTIFY_CISO", target=eid)
        add("ALERT_SOC_TIER2")
    elif cat == "phishing":
        add("BLOCK_IP", target=f"sender_domain:{ev['sender_domain']}")
        if ev["credentials_disclosed"] or ev["link_clicked"]:
            add("FORCE_MFA_RESET", target=eid)
        if ev["phishing_domain_hit"]:
            add("ALERT_SOC_TIER2", reason="Confirmed phishing domain")
        if ev["entity_type"] == "customer":
            add("NOTIFY_CUSTOMER", target=eid)
        add("MONITOR_72H", target=eid)
    elif cat == "social_engineering":
        add("ALERT_SOC_TIER2", reason="Impersonation attempt against staff")
        if ev["credentials_disclosed"]:
            add("FORCE_MFA_RESET", target=eid)
        add("NOTIFY_CISO", reason="Internal identity impersonated")
        add("MONITOR_72H", target=eid)
    elif cat == "false_positive":
        add("CLOSE_TICKET", reason="; ".join(ev.get("_why", []))[:200] or "Explained by corpus")
    else:
        add("ALERT_SOC_TIER2"); add("MONITOR_72H", target=eid)
    return A


def affected_systems(cat: str, ev: dict) -> str:
    if cat in ("false_positive", "prompt_injection"):
        return "none"
    raw = ev["raw"]
    s = []
    if cat == "ransomware":
        s = [ev["entity_id"]] + ev["lateral_targets"]
    elif cat in ("insider_threat", "data_exfiltration"):
        s = [ev.get("accessed_system") or ev["entity_id"]] + (["network_egress"] if ev["transfer_gb"] else [])
    elif cat == "api_abuse":
        s = ["api_gateway"]
    elif cat == "card_fraud":
        s = ["card_management", "payment_processing"]
    elif cat == "account_takeover":
        s = ["customer_accounts"] + (["payment_processing"] if raw.get("transaction_amount") else [])
    elif cat == "phishing":
        s = ["email_gateway"]
    elif cat == "social_engineering":
        emp = ev.get("employee") or {}
        s = [x.strip() for x in emp.get("approved_systems", "").split(",") if x.strip()][:3]
    return "|".join(dict.fromkeys(x for x in s if x)) or "none"


def risk_flags(cat: str, ev: dict) -> str:
    if cat == "false_positive" and not ev.get("injection"):
        return "NONE"
    f = []
    if cat == "prompt_injection" or ev.get("injection"):
        f.append("PROMPT_INJECTION_DETECTED")
    if ev["known_threat_actor"]:
        f.append("KNOWN_THREAT_ACTOR")
    if ev["active_fraud_flag"]:
        f.append("REPEAT_OFFENDER")
    if cat == "insider_threat":
        f.append("INSIDER_RISK")
    if cat in ("insider_threat", "data_exfiltration", "ransomware") and (ev["transfer_gb"] or ev["c2_ip"]):
        f.append("DATA_EXFILTRATION_RISK")
    if ev["resigned"]:
        f.append("RESIGNED_EMPLOYEE")
    if ev["privileged"]:
        f.append("PRIVILEGED_ACCOUNT")
    return "|".join(f) or "NONE"


def citations(cat: str, sev: str, rules: list[str], known_codes: set) -> str:
    codes = list(dict.fromkeys(rules))
    if cat != "false_positive" and sev in ("P1_CRITICAL", "P2_HIGH"):
        codes.append("PCI-DSS-10.6")       # P1/P2 must be reviewed within SLA
    codes.append("NOVAPAY-SEV-01")
    return ";".join(c for c in dict.fromkeys(codes) if not known_codes or c in known_codes)
