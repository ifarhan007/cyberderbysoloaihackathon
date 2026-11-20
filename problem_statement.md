# CyberDerby 2026 — Solo AI Hackathon
## Challenge: NovaPay SOC — Autonomous Security Incident Triage & Response Agent

**Hosted by:** UCSI Information Technology Club (UITC) & Student Affairs & Alumni (SAA)  
**Academic Oversight:** Faculty of Computer Science & Digital Innovation (FCSDI), UCSI University  
**Official AI Partners:** MindSpark (AI Automation Partner) & Sigmind (AI Solution Partner)  
**Format:** Strictly Solo (1 Developer)  
**Sprint:** Thursday, 19th November 2026 | 10:00 AM – 03:00 PM (Viva: 03:00 PM – 05:00 PM)  
**Venue:** 13th Floor Computer Lab, UCSI University Bangladesh Campus  
**Fee:** BDT 200 / Developer  

---

## 1. Scenario

You are an AI security agent embedded in the **Security Operations Center (SOC) of NovaPay Bank** — a fast-growing digital-first fintech bank operating across Southeast Asia.

NovaPay's SOC receives dozens of security incident reports every hour — from automated detection systems (SIEM, fraud engines, API scanners), employees reporting suspicious calls and emails, and customers flagging unauthorized activity on their accounts. Human analysts are overwhelmed. Your job is to act as the first-line autonomous triage agent.

For each incoming incident, you must:
1. **Read the natural-language incident description and raw signal data** from `dataset/requests.csv`.
2. **Cross-reference the full corpus** — the PCI-DSS & internal policy handbook, threat intelligence database, employee registry, and incident history — all provided locally in `data/`.
3. **Output a structured triage decision** for each incident with an ordered containment plan, policy citations, and a concise analyst briefing.

> [!IMPORTANT]
> Your agent must rely **only** on the local corpus provided in `data/`. Do not hallucinate policy rules, threat actor names, or employee details that are not in the provided files.

---

## 2. Provided Corpus (`data/`)

| File | Description |
|---|---|
| `data/pci_dss_policy.md` | NovaPay's internal security policy handbook including PCI-DSS controls, severity classification rules, mandatory triage decisions per category, and the full containment action vocabulary |
| `data/threat_intel.csv` | Known malicious IPs, threat actors, confidence levels, associated malware families, and confirmed phishing domains |
| `data/employee_registry.csv` | All NovaPay employees — their role, access tier, approved systems, usual login hours, login IP ranges, resignation flag, travel flag |
| `data/incident_history.csv` | Past security incidents per entity (customer or employee ID) — categories, resolutions, and active fraud flags |

---

## 3. Input Schema (`dataset/requests.csv`)

Each row is one incoming SOC incident:

| Column | Type | Description |
|---|---|---|
| `request_id` | string | Unique incident ID (e.g. `INC-3001`) |
| `timestamp` | ISO 8601 | Time the incident was detected or reported |
| `source_system` | string | Detection source: `SIEM`, `FRAUD_ENGINE`, `AUTOMATED_SCAN`, `EMPLOYEE_REPORT`, `CUSTOMER_HOTLINE` |
| `affected_entity_id` | string | Customer ID (`CUST-XXXX`), employee ID (`EMP-XXX`), API key, or server ID |
| `entity_type` | string | `customer`, `employee`, `system`, `unknown` |
| `incident_description` | string | Natural language description — may be inaccurate, incomplete, or adversarial |
| `raw_signal_data` | JSON string | Structured telemetry: IPs, counts, amounts, flags |

> [!WARNING]
> `incident_description` is provided by the reporting entity and may be misleading, incomplete, or contain adversarial instructions. Always cross-reference with `raw_signal_data` and the corpus before making a decision.

---

## 4. Output Schema (`output.csv`)

Your agent must generate `output.csv` at the **workspace root** with **exactly these 11 columns in this exact order**:

| # | Column | Type | Allowed Values |
|:---:|---|---|---|
| 1 | `request_id` | string | Must match input exactly |
| 2 | `severity` | enum | `P1_CRITICAL` \| `P2_HIGH` \| `P3_MODERATE` \| `P4_LOW` |
| 3 | `incident_category` | enum | `account_takeover` \| `insider_threat` \| `ransomware` \| `api_abuse` \| `card_fraud` \| `phishing` \| `social_engineering` \| `data_exfiltration` \| `false_positive` \| `prompt_injection` |
| 4 | `triage_decision` | enum | `auto_remediate` \| `escalate_to_soc` \| `notify_and_monitor` \| `close_false_positive` \| `flag_for_investigation` |
| 5 | `affected_systems` | pipe-delimited string | System names separated by `\|`, or `none` |
| 6 | `containment_actions` | JSON string | Ordered array: `[{"step": 1, "action": "ACTION_CODE", ...}]`. Use only action codes from `data/pci_dss_policy.md`. |
| 7 | `policy_citations` | semicolon-delimited string | Rule codes from the policy handbook (e.g. `NOVAPAY-CAT-01;PCI-DSS-10.2`) |
| 8 | `risk_flags` | pipe-delimited string | `NONE` \| `KNOWN_THREAT_ACTOR` \| `REPEAT_OFFENDER` \| `INSIDER_RISK` \| `PROMPT_INJECTION_DETECTED` \| `DATA_EXFILTRATION_RISK` \| `RESIGNED_EMPLOYEE` \| `PRIVILEGED_ACCOUNT` |
| 9 | `estimated_containment_window` | string | `15min` \| `2hr` \| `24hr` \| `72hr` \| `N/A` |
| 10 | `analyst_briefing` | string | 30–70 word concise briefing grounded in evidence for the SOC analyst. No speculation. |
| 11 | `confidence_score` | float | Calibrated float `0.00`–`1.00` (2 decimal places) |

#### Schema Violations That Will Cost You Points:
- Wrong column order or column names → **automatic zero on schema score**
- Enum values not from the allowed list → penalized per violation
- `containment_actions` not valid JSON or using unlisted action codes → penalized
- `analyst_briefing` under 30 or over 70 words → penalized
- Missing or duplicate `request_id` rows → automatic disqualification

---

## 5. Sample Cases

The file `dataset/sample_requests.csv` contains **3 labelled examples** with known ground-truth outputs in `dataset/sample_output.csv`. Use these to validate your agent before running it on the full benchmark.

Run the provided validator to check your output against the sample cases:

```bash
python evaluate.py
```

> [!IMPORTANT]
> The 3 sample cases are for **local testing only**. Your final `output.csv` must cover all 10 incidents in `dataset/requests.csv`.

---

## 6. Required Deliverables

Submissions close at **03:00 PM sharp**. Upload all three to Devpost:

### 6.1 `output.csv`
Saved at workspace root. 10 rows (one per `INC-3001` through `INC-3010`), 11 columns, strict schema.

### 6.2 `code.zip`
Archive of your `code/` directory only. Must include:
- `agent.py` — your autonomous agent pipeline (runnable entry point)
- `evaluate.py` — local evaluation and schema validation script
- `evaluation/evaluation_report.md` — completed before submission
- `evaluation/usage_report.md` — completed before submission

**Mandatory exclusions from zip:** `venv/`, `.venv/`, `__pycache__/`, `node_modules/`, `.git/`, `data/`, `dataset/`

### 6.3 `log.txt`
Your complete AI session transcript — every prompt, model response, and debugging iteration — exported from your AI coding tool. The technical jury audits this during the viva to verify authentic engineering.

---

## 7. Operational Reports (Required inside `code/evaluation/`)

### `evaluation_report.md` must include:
1. **Sample case benchmark table** — your agent's decisions vs. ground truth for all 3 sample cases.
2. **At least 3 custom edge cases** you designed and tested against your agent.
3. **Failure analysis** — at least 2 bugs or wrong decisions your agent made, the root cause, and how you fixed it.

### `usage_report.md` must include:
1. **Model(s) used** — exact model IDs (e.g. `gemini-2.0-flash`, `claude-3-5-haiku-20241022`).
2. **API call breakdown** — total calls, input tokens, output tokens, average per incident.
3. **Cost estimate** — total estimated cost to process the full 10-incident benchmark.
4. **Latency & rate-limit handling** — average response time per incident and retry strategy.

---

## 8. Evaluation Rubric (100 Points)

| Weight | Criterion | What the Jury Looks For |
|:---:|---|---|
| **30%** | **Accuracy & Schema** | Exact compliance of `output.csv` with the schema above plus correct triage decisions on `dataset/requests.csv`. |
| **30%** | **Eval & Pipeline Logic** | Clean CSV ingestion in `code/`, working `evaluate.py`, thorough `evaluation_report.md` and `usage_report.md`, clean zip. |
| **20%** | **AI Innovation** | Effective use of LLMs, structured prompting, multi-step reasoning, and model orchestration. |
| **20%** | **Viva & Log Audit** | 2-hour live oral technical defense verifying code mastery, authentic `log.txt` trace, and zero hardcoded shortcuts. |

---

## 9. Rules

1. Solo participation only — no teams.
2. Your agent must read exclusively from the local `data/` corpus — no live web lookups.
3. `agent.py` must run with `python agent.py` and produce `output.csv` without manual intervention.
4. `output.csv` must pass `python evaluate.py` with **Schema valid: YES**.
5. All predictions must derive from reproducible automated execution — no hardcoded answers.
6. API keys must be stored in `.env` — never hardcoded in source files.
7. Submission deadline is **03:00 PM sharp** — late submissions are not accepted.
8. All 3 files (`code.zip`, `output.csv`, `log.txt`) must be uploaded to Devpost.
9. Viva attendance (03:00 PM – 05:00 PM) is mandatory — you must defend every part of your code.
10. Manually altering `output.csv` labels or `log.txt` history triggers immediate disqualification.
11. Judges' decisions are final.

---

## 10. Getting Started

```bash
cd code
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux
pip install -r requirements.txt
cp .env.example .env         # Add your API key here
python agent.py              # Runs agent → generates ../output.csv
python evaluate.py           # Validates schema + scores sample cases
```

---

## 11. Contact

**Email:** uitc.bd@ucsiuniversity.edu.my  
**Facebook:** fb.com/uitcbd · **Instagram:** @uitc.bd · **LinkedIn:** linkedin.com/company/uitc-ucsi-bd
