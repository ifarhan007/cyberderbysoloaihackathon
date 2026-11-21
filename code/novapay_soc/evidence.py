"""
Step 1 — Evidence gathering (deterministic, no AI).

Turns one raw incident row into a dictionary of verified FACTS by
cross-referencing the corpus: threat-intel hits, employee registry checks,
incident history, and numeric signals from raw_signal_data.

The free-text incident_description is treated as UNTRUSTED. Facts are taken
from raw_signal_data and the corpus wherever possible.
"""

import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone

from .corpus import Corpus

# Local-time offsets for countries appearing in the registry (policy hours are local).
TZ_OFFSETS = {"BD": 6, "SG": 8, "MY": 8, "AE": 4, "NG": 1}

INJECTION_PATTERNS = [
    r"\b(system|admin|policy)\s+override\b",
    r"\b(disregard|ignore|bypass|forget)\b.{0,40}\b(policy|policies|rules?|instructions?|guidelines?)\b",
    r"\bclassify\s+(this\s+)?(as|it\s+as)\s+\w+",
    r"\b(close|resolve)\s+(this\s+|the\s+ticket\s+)?immediately\b",
    r"\bno\s+further\s+action\s+(is\s+)?required\b",
    r"\balready\s+been\s+(reviewed|approved)\s+by\b",
    r"\bpriority\s*:\s*P[1-4]",
    r"\bset\s+severity\b",
    r"\byou\s+are\s+now\b",
    r"\bnew\s+instructions?\b",
]
_INJ = [re.compile(p, re.I) for p in INJECTION_PATTERNS]
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _parse_raw(raw: str) -> tuple[dict, str | None]:
    if not raw:
        return {}, None
    try:
        data = json.loads(raw)
        return (data, None) if isinstance(data, dict) else ({}, "raw_signal_data is not a JSON object")
    except json.JSONDecodeError as e:
        return {}, f"raw_signal_data is not valid JSON ({e.msg})"


def _bool(v) -> bool:
    return str(v).strip().upper() == "TRUE" if not isinstance(v, bool) else v


def _parse_ts(ts: str):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _in_hours(hour: float, window: str) -> bool | None:
    if not window or window.upper() == "UNRESTRICTED":
        return True
    m = re.match(r"(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})", window)
    if not m:
        return None
    start, end = int(m[1]) + int(m[2]) / 60, int(m[3]) + int(m[4]) / 60
    return start <= hour < end


def _ip_in_range(ip: str, cidr: str) -> bool | None:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None


def _num(raw: dict, *keys, default=0):
    for k in keys:
        if k in raw:
            try:
                return float(raw[k])
            except (TypeError, ValueError):
                pass
    return default


def build_evidence(inc: dict, corpus: Corpus) -> dict:
    desc = inc.get("incident_description", "")
    raw, raw_error = _parse_raw(inc.get("raw_signal_data", ""))
    eid = inc.get("affected_entity_id", "").strip()
    ts = _parse_ts(inc.get("timestamp", ""))
    notes: list[str] = []   # human-readable evidence lines (fed to the LLM and the UI)

    ev: dict = {
        "request_id": inc.get("request_id", ""),
        "entity_id": eid,
        "entity_type": inc.get("entity_type", "unknown"),
        "source_system": inc.get("source_system", ""),
        "timestamp": inc.get("timestamp", ""),
        "raw": raw,
        "raw_error": raw_error,
    }
    if raw_error:
        notes.append(f"Data quality: {raw_error}; relying on corpus and description only.")

    # ── Prompt-injection / tampering detection ───────────────────────────
    hits = [m.group(0) for rx in _INJ for m in [rx.search(desc)] if m]
    tamper_signals = []
    if raw.get("ciso_ticket_exists") is False or str(raw.get("ciso_ticket_exists")).lower() == "false":
        tamper_signals.append("claimed CISO approval has no matching ticket")
    if str(raw.get("instruction_type", "")).startswith("directive"):
        tamper_signals.append(f"submission contains a directive ({raw['instruction_type']})")
    ev["injection_phrases"] = hits
    ev["injection"] = bool(hits) and (len(hits) >= 2 or bool(tamper_signals))
    if hits:
        notes.append(f"Description contains instruction-like phrases: {', '.join(repr(h) for h in hits[:4])}.")
    notes += [f"Tampering signal: {s}." for s in tamper_signals]

    # ── Threat intel: every IP found in raw signals ───────────────────────
    ip_fields = {}
    for k, v in raw.items():
        if isinstance(v, str) and _IP_RE.fullmatch(v.strip()):
            ip_fields[k] = v.strip()
    ti_hits, safe_ips = [], []
    for field_name, ip in ip_fields.items():
        row = corpus.threat_ips.get(ip)
        if not row:
            continue
        if row["confidence"].upper() in ("", "NONE"):
            safe_ips.append({"ip": ip, "field": field_name, **row})
            notes.append(f"{field_name} {ip} is listed as safe ({row['threat_actor']}: {row['notes']}).")
        else:
            ti_hits.append({"ip": ip, "field": field_name, **row})
            notes.append(f"{field_name} {ip} matches threat intel: {row['threat_category']} / "
                         f"{row['threat_actor']} (confidence {row['confidence']}).")
    ev["threat_hits"] = ti_hits
    ev["safe_ips"] = safe_ips
    ev["known_threat_actor"] = any(h["confidence"].upper() in ("MEDIUM", "HIGH", "CRITICAL") for h in ti_hits)

    sender = str(raw.get("sender_domain", "")).lower().strip()
    if not sender:
        m = re.search(r"@([a-z0-9.\-]+\.[a-z]{2,})", desc, re.I)
        sender = m.group(1).lower() if m else ""
    ev["sender_domain"] = sender
    ev["phishing_domain_hit"] = corpus.phishing_domains.get(sender) if sender else None
    if sender:
        if ev["phishing_domain_hit"]:
            d = ev["phishing_domain_hit"]
            notes.append(f"Sender domain {sender} is a CONFIRMED phishing domain ({d['threat_actor']}, {d['confidence']}).")
            ev["known_threat_actor"] = True
        else:
            notes.append(f"Sender domain {sender} is NOT in the known phishing-domain list.")

    # ── Employee registry ─────────────────────────────────────────────────
    emp_id = eid if eid in corpus.employees else str(raw.get("employee_id", ""))
    emp = corpus.employees.get(emp_id)
    ev["employee"] = emp
    if emp:
        tier = emp["access_tier"]
        approved = [s.strip() for s in emp["approved_systems"].split(",") if s.strip()]
        ev["privileged"] = tier in ("PRIVILEGED", "ADMIN")
        ev["resigned"] = _bool(emp["resignation_flag"])
        ev["after_hours_ticket"] = _bool(emp["after_hours_ticket_active"])
        ev["travel_flag"] = _bool(emp["travel_flag"])
        ev["travel_country"] = emp["travel_country"]
        notes.append(f"Registry: {emp_id} {emp['full_name']}, {emp['role']}, tier {tier}, "
                     f"approved systems [{', '.join(approved)}].")
        if ev["resigned"]:
            notes.append(f"Registry: resignation flag is ACTIVE ({emp['notes']}).")
        if ev["travel_flag"]:
            notes.append(f"Registry: travel flag ACTIVE for {emp['travel_country']} ({emp['notes']}).")

        system = raw.get("accessed_system") or raw.get("system")
        if system:
            in_scope = "all_systems" in approved or system in approved
            ev["accessed_system"] = system
            ev["system_in_scope"] = in_scope
            notes.append(f"Accessed system {system} is {'WITHIN' if in_scope else 'OUTSIDE'} approved scope.")

        login_ip = raw.get("login_ip") or raw.get("source_ip")
        if login_ip and emp["usual_login_ip_range"]:
            ev["ip_in_usual_range"] = _ip_in_range(login_ip, emp["usual_login_ip_range"])
            notes.append(f"Login IP {login_ip} {'is' if ev['ip_in_usual_range'] else 'is NOT'} in usual range "
                         f"{emp['usual_login_ip_range']}.")

        # Local hour of the event (policy hours are local time)
        hour_utc = _num(raw, "login_hour_utc", default=None)
        if hour_utc is None and ts is not None:
            hour_utc = ts.hour + ts.minute / 60
        if hour_utc is not None:
            offset = TZ_OFFSETS.get(emp["usual_login_country"], 0)
            local = (hour_utc + offset) % 24
            ev["local_hour"] = round(local, 2)
            ev["anomalous_hours"] = 0 <= local < 5
            ev["within_usual_hours"] = _in_hours(local, emp["usual_login_hours"])
            notes.append(f"Event at {local:05.2f}h local ({emp['usual_login_country']}); usual hours "
                         f"{emp['usual_login_hours']} -> {'inside' if ev['within_usual_hours'] else 'outside'}.")
    else:
        ev["privileged"] = False
        ev["resigned"] = False
        ev["travel_flag"] = False

    # ── Incident history (fraud flag within 90 days) ──────────────────────
    hist = corpus.history.get(eid, [])
    ev["history"] = hist
    recent_flag = []
    for h in hist:
        if _bool(h["fraud_flag_active"]):
            d = _parse_ts(h["incident_date"] + "T00:00:00+00:00")
            if ts is None or d is None or ts - d <= timedelta(days=90):
                recent_flag.append(h)
    if _bool(raw.get("prior_fraud_flag", False)) and not recent_flag:
        notes.append("raw_signal_data claims a prior fraud flag; NOT confirmed by incident_history.csv.")
    ev["active_fraud_flag"] = bool(recent_flag)
    for h in hist:
        notes.append(f"History: {h['incident_date']} {h['incident_category']} ({h['severity']}, "
                     f"{h['resolution']}, fraud_flag={h['fraud_flag_active']}) — {h['notes']}")
    if not hist:
        notes.append(f"History: no prior incidents for {eid or 'this entity'}.")

    # ── Numeric signals ───────────────────────────────────────────────────
    ev["mfa_failures"] = _num(raw, "mfa_failures")
    ev["tx_amount"] = _num(raw, "transaction_amount")
    ev["minutes_since_login"] = _num(raw, "minutes_since_login", default=None)
    ev["geo_country"] = str(raw.get("geo_country", "")).upper()
    ev["rpm"] = _num(raw, "requests_per_minute")
    ev["fail_rate"] = _num(raw, "http_401_rate")
    ev["failed_logins"] = _num(raw, "failed_login_attempts", "failed_logins")
    ev["endpoint"] = raw.get("endpoint", "")
    amounts = raw.get("transaction_amounts") or []
    amounts = [float(a) for a in amounts if isinstance(a, (int, float))]
    ev["micro_tx_count"] = sum(1 for a in amounts if a < 2.0)
    ev["micro_window"] = _num(raw, "window_minutes", default=None)
    ev["transfer_gb"] = _num(raw, "file_size_gb", "outbound_gb")
    if not ev["transfer_gb"] and "outbound_mb" in raw:
        ev["transfer_gb"] = _num(raw, "outbound_mb") / 1024
    ev["destination_ip"] = raw.get("destination_ip", "")
    ev["files_encrypted"] = _num(raw, "files_encrypted")
    ev["shadow_copy_deleted"] = _bool(raw.get("shadow_copy_deleted", False))
    ev["lateral_targets"] = [t for t in raw.get("lateral_movement_targets", []) if isinstance(t, str)]
    ev["c2_ip"] = raw.get("c2_beacon_ip", "")
    ev["report_type"] = str(raw.get("report_type", "")).lower()
    ev["impersonation"] = bool(raw.get("caller_claimed_identity")) or bool(
        re.search(r"\b(claiming|pretending|impersonat)\w*\b", desc, re.I))
    ev["credentials_disclosed"] = _bool(raw.get("credentials_disclosed", False)) or _bool(raw.get("data_disclosed", False))
    ev["link_clicked"] = _bool(raw.get("link_clicked", False))
    ev["data_exported"] = _bool(raw.get("data_exported", False))
    ev["customer_travel"] = _bool(raw.get("customer_travel_flag", False))
    ev["post_login_tx"] = _num(raw, "transaction_count_post_login", default=None)

    ev["notes"] = notes
    return ev
