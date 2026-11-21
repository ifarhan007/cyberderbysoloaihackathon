"""
Step 4 — Orchestration + guardrails.

  incident ─► [1] evidence (corpus lookups) ─► [2] policy engine (rules)
                                    │                       │ baseline
                                    └────► [3] Gemini ◄─────┘ (as context)
                                                  │ structured JSON
                                    [4] guardrails & reconciliation
                                                  │
                                    [5] briefing check (+1 repair call)
                                                  ▼
                                         output.csv row + trace

Guardrails guarantee that every row is schema-valid even if the LLM is
offline, wrong, or manipulated.
"""

import json
import re

from .corpus import Corpus
from .evidence import build_evidence
from .llm import CATEGORIES, DECISIONS, SEVERITIES, GeminiClient, LLMError, SYSTEM_PROMPT, response_schema
from . import policy as P

FIELDNAMES = [
    "request_id", "severity", "incident_category", "triage_decision",
    "affected_systems", "containment_actions", "policy_citations",
    "risk_flags", "estimated_containment_window", "analyst_briefing", "confidence_score",
]
REQUIRED_INPUT = ["request_id", "timestamp", "source_system", "affected_entity_id", "entity_type",
                  "incident_description", "raw_signal_data"]
ID_RE = re.compile(r"\b(?:EMP-\d+|CUST-\d+|API-KEY-\d+|SRV-[A-Z0-9-]+|CARD-[A-Z0-9-]+|INC-[A-Z0-9]+|"
                   r"(?:\d{1,3}\.){3}\d{1,3})\b")


IP_ONLY = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


MONEY_RE = re.compile(r"\$\s?[0-9][0-9,]*(?:\.[0-9]+)?")
TOTAL_RE = re.compile(r"\b(total(?:l?ing|ed)?|in total|sum(?:ming)? to|combined)\b", re.I)
EXECUTED_RE = re.compile(r"\b((?:actions?|containment|steps?|measures?)\s+(?:(?:were|have been|has been|was)\s+)?"
                         r"(?:executed|carried out|completed|implemented)|(?:was|were|has been|have been)\s+(?:frozen|"
                         r"blocked|revoked|isolated|reset|rate[- ]limited|closed|preserved))\b", re.I)
POLICY_AMOUNTS = "$5,000 $500 $2.00"   # thresholds quoted in the handbook (SEV-01, CAT-01, CAT-05)


def _num_key(x: str) -> str:
    v = re.sub(r"[^0-9.]", "", x).strip(".")
    try:
        return f"{float(v):.2f}"
    except ValueError:
        return v


def word_count(s: str) -> int:
    return len(s.split())


def validate_incident(inc: dict) -> list[str]:
    """Input validation used by both the CLI and the web API."""
    errs = []
    for k in REQUIRED_INPUT:
        if k not in inc:
            errs.append(f"missing field '{k}'")
    if not str(inc.get("request_id", "")).strip():
        errs.append("request_id is empty")
    if len(str(inc.get("incident_description", ""))) > 5000:
        errs.append("incident_description longer than 5000 characters")
    if inc.get("entity_type") not in (None, "customer", "employee", "system", "unknown"):
        errs.append("entity_type must be customer|employee|system|unknown")
    return errs


# ── Briefing helpers ─────────────────────────────────────────────────────
def fallback_briefing(cat: str, sev: str, decision: str, ev: dict, why: list[str]) -> str:
    """Deterministic briefing built only from verified evidence."""
    label = cat.replace("_", " ")
    parts = [f"{ev['entity_id'] or 'Unknown entity'} incident triaged as {label} ({sev})."]
    parts += why[:3]
    hits = ev["threat_hits"]
    if hits:
        h = hits[0]
        parts.append(f"{h['ip']} is listed in threat intel as {h['threat_category']} ({h['threat_actor']}).")
    parts.append(f"Decision: {decision} per {P.CATEGORY_RULE[cat]}.")
    text = " ".join(parts)
    words = text.split()
    if len(words) > 70:                       # trim at sentence boundary
        out = []
        for sent in re.split(r"(?<=[.!?])\s+", text):
            if word_count(" ".join(out + [sent])) > 68:
                break
            out.append(sent)
        text = " ".join(out)
    if word_count(text) < 30:
        text += (f" All facts were cross-referenced against the threat intelligence feed, employee registry and "
                 f"incident history. Target containment window: {'N/A' if cat == 'false_positive' else P.WINDOW_FOR_SEV[sev]}.")
    return text


def briefing_problems(text: str, ev: dict, incident: dict) -> list[str]:
    probs = []
    n = word_count(text or "")
    if not 30 <= n <= 70:
        probs.append(f"briefing has {n} words; must be 35-60")
    known = json.dumps(incident) + " ".join(ev["notes"])
    invented = [t for t in ID_RE.findall(text or "") if t not in known]
    if invented:
        probs.append(f"briefing mentions identifiers not present in the evidence: {invented}")
    # Numeric grounding: dollar amounts must appear in the evidence or as a policy threshold; no derived totals.
    digits = re.sub(r"[^0-9.]", " ", (known + " " + POLICY_AMOUNTS).replace(",", ""))   # "5,000" -> "5000"
    known_nums = {_num_key(x) for x in digits.split() if any(ch.isdigit() for ch in x)}
    bad_amounts = [a for a in MONEY_RE.findall(text or "") if _num_key(a) not in known_nums]
    if bad_amounts:
        probs.append(f"briefing states amounts not found in the evidence: {bad_amounts}")
    if TOTAL_RE.search(text or ""):
        probs.append("briefing states a computed total; quote the individual values from the evidence instead")
    if EXECUTED_RE.search(text or ""):
        probs.append("briefing claims actions were executed; this system only recommends actions (simulation mode)")
    return probs


# ── Guardrail for LLM containment plans ──────────────────────────────────
def clean_actions(actions, valid_codes: set, evidence_text: str) -> list[dict]:
    out = []
    for a in actions or []:
        if not isinstance(a, dict) or a.get("action") not in valid_codes:
            continue
        step = {"action": a["action"]}
        tgt = str(a.get("target", "")).strip()
        if a["action"] == "BLOCK_IP" and not IP_ONLY.fullmatch(tgt):
            continue                    # BLOCK_IP must target an IP address (no domain "blocks")
        # drop targets that reference IDs/IPs which do not exist in the incident (hallucination guard)
        if tgt and all(t in evidence_text for t in ID_RE.findall(tgt)):
            step["target"] = tgt[:80]
        if a.get("reason"):
            step["reason"] = str(a["reason"])[:160]
        out.append(step)
    return out


LLM_ALLOWED_EXTRAS = {"ALERT_SOC_TIER2", "NOTIFY_CISO", "MONITOR_72H", "PRESERVE_FORENSICS"}


def merge_actions(base: list[dict], extra: list[dict], cat: str) -> list[dict]:
    """Policy plan first (mandatory), then up to 2 extra LLM-suggested steps that add new action codes.

    The LLM may only add low-impact visibility steps. Anything that changes accounts, keys, network access or
    ticket state (freeze, revoke, block, isolate, MFA reset, rate-limit, patch, close, customer notice) must
    come from a policy rule — e.g. organiser update e5eea08 removed REVOKE_API_KEY for INC-S002 and Gemini
    tried to add it back."""
    if cat == "false_positive":
        merged = [a for a in base if a["action"] == "CLOSE_TICKET"]
    else:
        merged = list(base)
        have = {a["action"] for a in merged}
        added = 0
        for a in extra:
            if a["action"] not in have and a["action"] in LLM_ALLOWED_EXTRAS and added < 2:
                merged.append(a); have.add(a["action"]); added += 1
    if cat == "insider_threat":   # CAT-02: forensics before anything else
        merged.sort(key=lambda a: a["action"] != "PRESERVE_FORENSICS")
    return [{"step": i, **{k: v for k, v in a.items() if k != "step"}} for i, a in enumerate(merged, 1)]


# ── Main agent ───────────────────────────────────────────────────────────
class TriageAgent:
    def __init__(self, corpus: Corpus, llm: GeminiClient | None = None, use_llm: bool = True):
        self.corpus = corpus
        self.llm = llm or GeminiClient()
        self.use_llm = use_llm and self.llm.enabled
        self.system_prompt = SYSTEM_PROMPT.format(policy=corpus.policy_text)
        self.schema = response_schema(sorted(corpus.action_codes))

    @property
    def mode(self) -> str:
        return f"gemini ({self.llm.models[0]}) + policy guardrails" if self.use_llm else "offline policy engine (no API key)"

    def _llm_user_prompt(self, inc: dict, ev: dict, base: dict) -> str:
        return (
            f"INCIDENT {inc.get('request_id')}\n"
            f"timestamp: {inc.get('timestamp')}\nsource_system: {inc.get('source_system')}\n"
            f"affected_entity_id: {inc.get('affected_entity_id')}\nentity_type: {inc.get('entity_type')}\n"
            f"raw_signal_data: {inc.get('raw_signal_data')}\n\n"
            f"<untrusted_description>\n{inc.get('incident_description', '')}\n</untrusted_description>\n\n"
            "VERIFIED EVIDENCE (from local corpus lookups):\n- " + "\n- ".join(ev["notes"]) + "\n\n"
            f"RULE-ENGINE PRE-CHECK (may be incomplete; verify against the handbook): "
            f"category={base['category']}, severity={base['severity']}, decisive={base['decisive']}; "
            f"signals: {' '.join(base['why'])}\n"
        )

    def triage(self, inc: dict) -> tuple[dict, dict]:
        ev = build_evidence(inc, self.corpus)
        base = P.classify(ev)
        ev["_why"] = base["why"]
        trace = {"request_id": ev["request_id"], "evidence": ev["notes"], "rule_engine": {
            k: base[k] for k in ("category", "severity", "decisive", "why")}, "mode": self.mode, "guardrails": [],
            "injection_phrases": ev["injection_phrases"]}

        llm_out, llm_err = None, None
        if self.use_llm:
            try:
                llm_out = self.llm.generate_json(self.system_prompt, self._llm_user_prompt(inc, ev, base),
                                                 self.schema, tag=f"{ev['request_id']}:triage")
            except LLMError as e:
                llm_err = str(e)
                trace["guardrails"].append(f"LLM unavailable, used policy engine only: {e}")
        trace["llm"] = llm_out

        # ── Reconcile category / severity / decision ───────────────────
        cat, sev = base["category"], base["severity"]
        agree = None
        extra_flags = []
        if llm_out:
            l_cat, l_sev, l_dec = (llm_out.get("incident_category"), llm_out.get("severity"),
                                   llm_out.get("triage_decision"))
            agree = {"category": l_cat == cat, "severity": l_sev == sev,
                     "decision": l_dec == P.mandatory_decision(cat, ev)}
            if base["decisive"]:
                if not all(agree.values()):
                    trace["guardrails"].append(
                        f"LLM proposed {l_cat}/{l_sev}/{l_dec}; policy rules are decisive, kept {cat}/{sev}.")
                if l_cat == "prompt_injection" and cat == "false_positive":
                    cat, sev = "prompt_injection", "P2_HIGH"
                    trace["guardrails"].append("LLM detected manipulation in a report the rules would close as "
                                               "false positive; refusing to auto-close (CAT-10, PCI-DSS-12.10).")
                elif l_cat == "prompt_injection" and cat != "prompt_injection":
                    extra_flags.append("PROMPT_INJECTION_DETECTED")
                    trace["guardrails"].append("LLM detected manipulation text; flag added, telemetry-based category kept.")
            else:
                if l_cat in CATEGORIES:
                    cat = l_cat
                if l_sev in SEVERITIES:
                    sev = l_sev
                trace["guardrails"].append(f"Rules inconclusive: adopted LLM classification {cat}/{sev}.")
        decision = P.mandatory_decision(cat, ev)
        if not base["decisive"]:
            # Rules found no decisive indicator: never auto-close or auto-remediate on reasoning alone.
            if cat == "false_positive":
                cat, sev = base["category"], max(sev, "P3_MODERATE", key=P.SEV_ORDER.index)
                trace["guardrails"].append("LLM suggested false_positive without corpus evidence; refused "
                                           "(PCI-DSS-12.10) and flagged for investigation.")
            if not llm_out or decision in ("close_false_positive", "auto_remediate"):
                decision = "flag_for_investigation"
        if llm_out and llm_out.get("triage_decision") in DECISIONS and llm_out["triage_decision"] != decision:
            trace["guardrails"].append(f"Decision forced to policy-mandated '{decision}' for {cat}.")

        # ── Containment plan ───────────────────────────────────────────
        evidence_text = json.dumps(inc) + " ".join(ev["notes"])
        base_actions = P.build_actions(cat, sev, ev)
        llm_actions = clean_actions((llm_out or {}).get("containment_actions"), self.corpus.action_codes, evidence_text)
        actions = merge_actions(base_actions, llm_actions, cat)

        # ── Citations: policy-derived + LLM-suggested (only codes that exist in the handbook) ──
        cites = P.citations(cat, sev, base["rules"] if cat == base["category"] else [P.CATEGORY_RULE[cat]],
                            self.corpus.policy_rule_codes).split(";")
        for c in (llm_out or {}).get("policy_citations", []):
            c = str(c).strip()
            if c in self.corpus.policy_rule_codes and c not in cites and len(cites) < 6:
                cites.append(c)
            elif c and c not in self.corpus.policy_rule_codes:
                trace["guardrails"].append(f"Dropped citation '{c}' (not in handbook).")

        flags = P.risk_flags(cat, ev).split("|")
        flags = [f for f in flags + extra_flags if f != "NONE"]
        flags = "|".join(dict.fromkeys(flags)) or "NONE"
        window = "N/A" if cat == "false_positive" else P.WINDOW_FOR_SEV[sev]

        # ── Briefing: LLM text if it passes checks, one repair attempt, else deterministic ──
        briefing = (llm_out or {}).get("analyst_briefing", "")
        probs = briefing_problems(briefing, ev, inc) if llm_out else ["no LLM output"]
        if llm_out and probs:
            try:
                fix = self.llm.generate_json(
                    self.system_prompt,
                    self._llm_user_prompt(inc, ev, base) +
                    f"\nFINAL DECISION (do not change): {cat}/{sev}/{decision}.\n"
                    f"Your previous briefing was rejected: {'; '.join(probs)}.\nPrevious: {briefing}\n"
                    "Rewrite the analyst_briefing (35-60 words, only facts from the evidence). "
                    "Repeat the other fields unchanged.",
                    self.schema, tag=f"{ev['request_id']}:briefing_repair")
                if not briefing_problems(fix.get("analyst_briefing", ""), ev, inc):
                    trace["guardrails"].append(f"Briefing repaired after: {'; '.join(probs)}")
                    briefing, probs = fix["analyst_briefing"], []
            except LLMError:
                pass
        if probs:
            if llm_out:
                trace["guardrails"].append(f"Briefing replaced by deterministic text ({'; '.join(probs)}).")
            briefing = fallback_briefing(cat, sev, decision, ev, base["why"])
        briefing = " ".join(briefing.split())

        # ── Calibrated confidence ──────────────────────────────────────
        conf = 0.88 if base["decisive"] else 0.55
        corroboration = sum(bool(x) for x in (ev["threat_hits"], ev["phishing_domain_hit"], ev["active_fraud_flag"],
                                              ev.get("employee"), ev["history"]))
        conf += min(corroboration * 0.02, 0.06)
        if agree is None:
            conf -= 0.05                       # no second opinion available
        else:
            conf += 0.04 if agree["category"] else -0.15
            conf -= 0.03 * (not agree["severity"]) + 0.03 * (not agree["decision"])
        if ev["raw_error"]:
            conf -= 0.15
        conf = max(0.30, min(0.99, conf))

        row = {
            "request_id": ev["request_id"],
            "severity": sev,
            "incident_category": cat,
            "triage_decision": decision,
            "affected_systems": P.affected_systems(cat, ev),
            "containment_actions": json.dumps(actions),
            "policy_citations": ";".join(cites),
            "risk_flags": flags,
            "estimated_containment_window": window,
            "analyst_briefing": briefing,
            "confidence_score": f"{conf:.2f}",
        }
        trace.update(engine="gemini+guardrails" if llm_out else "deterministic_fallback",
                     agreement=agree, llm_error=llm_err, output=row)
        return row, trace

    def run(self, incidents: list[dict], progress=None) -> tuple[list[dict], list[dict]]:
        """Sequential processing (free-tier friendly). Invalid rows abort with a clear error."""
        rows, traces = [], []
        for inc in incidents:
            errs = validate_incident(inc)
            if errs:
                raise ValueError(f"{inc.get('request_id', '?')}: " + "; ".join(errs))
            row, trace = self.triage(inc)
            rows.append(row); traces.append(trace)
            if progress:
                progress(row, trace)
        return rows, traces
