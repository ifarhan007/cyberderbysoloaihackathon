# NovaPay SOC Triage Agent — how it works

A hybrid AI agent: **deterministic corpus lookups + policy rules + Gemini reasoning + guardrails**.
It only *recommends* containment actions (simulation mode); it never touches real accounts or systems.

## Pipeline (one incident)

```
requests.csv row
   │
   ▼
[1] soc/evidence.py  — parse raw_signal_data safely, look up every IP in threat_intel.csv,
   │                   sender domain in the phishing list, employee in the registry
   │                   (scope, IP range, local hours, resignation, travel), incident history
   │                   (fraud flag within 90 days), detect prompt-injection phrases.
   ▼
[2] soc/policy.py    — encodes NOVAPAY-CAT-01..10 and SEV-01/02 as rules. Gives a baseline
   │                   category/severity and says whether the match is DECISIVE.
   ▼
[3] soc/llm.py       — Gemini (official google-genai SDK) gets the policy handbook, the verified
   │                   evidence, and the description wrapped in <untrusted_description>.
   │                   It must answer in a JSON schema (enums are enforced by the API).
   ▼
[4] soc/pipeline.py  — guardrails:
   │   • decisive rule match  → category/severity locked; LLM is a second opinion (affects confidence)
   │   • inconclusive         → LLM classification used, but never auto-close / auto-remediate
   │   • triage_decision always = the policy's mandatory decision for the category
   │   • action codes / rule codes must exist in the handbook; invented IPs/IDs are dropped
   │   • briefing must be 30–70 words and mention only IDs/IPs in the evidence (1 repair call,
   │     then deterministic briefing)
   │   • Gemini down / quota exhausted → deterministic engine, run continues
   ▼
output.csv row  +  evaluation/trace_*.json (evidence, rules, LLM reasoning, guardrail actions, engine)
```

## Why hybrid? (viva answer)
* Rules are **auditable and repeatable** — a bank cannot let an LLM's mood decide P1 vs P4.
* The LLM adds **reasoning on messy/novel text**, writes evidence-grounded briefings, proposes extra
  containment steps, detects manipulation the regexes miss, and acts as a second opinion that
  calibrates the confidence score.
* Guardrails make every row **schema-valid even if the LLM fails, hallucinates, or is manipulated**.

## Windows Command Prompt

```bat
cd cyberderbysoloaihackathon\code
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
notepad .env
python agent.py --samples
python agent.py
python evaluate.py
python -m unittest discover -s tests -v
python package_submission.py
```

`notepad .env` → paste your key after `GEMINI_API_KEY=` and save.

Optional: `set RUN_LLM_TESTS=1` before the unittest command runs the edge cases through Gemini too.
`python agent.py --offline` runs without any API calls (deterministic engine only).

## Files
| File | Role |
|---|---|
| `agent.py` | CLI entry point; writes `../output.csv`, traces and usage logs |
| `soc/corpus.py` | loads data/ once; parses rule codes + action codes from the handbook |
| `soc/evidence.py` | per-incident evidence gathering and injection detection |
| `soc/policy.py` | policy rules, containment plans, risk flags, citations |
| `soc/llm.py` | Gemini client: JSON schema, retries, model fallback, quota circuit breaker |
| `soc/pipeline.py` | orchestration, guardrails, confidence calibration |
| `evaluate.py` | schema validator + sample scoring (organiser's script, extended) |
| `tests/test_edge_cases.py` | custom edge cases + regression tests for starter-code bugs |
| `package_submission.py` | builds `../code.zip` (excludes .env, venv, caches, data) |

## Viva cheat-sheet

**Q: Where is the AI?** `soc/llm.py` sends Gemini the handbook, the verified evidence and the
untrusted description, and gets back schema-enforced JSON (category, severity, decision, plan,
citations, briefing, reasoning). It writes the briefings, proposes extra containment steps, catches
manipulation, and is the second opinion behind the confidence score.

**Q: Why not let Gemini decide everything?** In our own tests it got two cases wrong: EDGE-02
(travel flag hid MFA failures plus a $7,200 transfer) and EDGE-07 (it closed an unreadable alert
as a false positive). For a bank, P1 vs P4 must be auditable, so decisive policy rules lock the
decision and Gemini is overruled. The trace shows every override.

**Q: How do you stop prompt injection?** (1) Regex detection runs before any AI call.
(2) The description sits inside `<untrusted_description>` and the system prompt forbids obeying it.
(3) Telemetry decides the category, so injected text cannot turn a real attack into a closed ticket.
(4) A manipulated report can never be auto-closed.

**Q: Are answers hardcoded?** No. Each decision follows from thresholds in the handbook, applied to
the fields in `raw_signal_data` and the corpus. The new edge cases (EDGE-01…08) are incidents the
agent has never seen, and it handles them correctly.

**Q: What if the API fails?** Each call is retried with backoff. A model that hits its daily quota
is skipped and the next fallback model is used. If every model fails, the deterministic engine
triages the incident. Every row records which engine produced it.

**Q: How is confidence calibrated?** It starts at 0.88 for a decisive rule match (0.55 when
inconclusive). It gains up to +0.06 for corroborating corpus evidence and +0.04 when Gemini agrees
on the category. It loses 0.15 when Gemini disagrees on the category, 0.03 for each severity or
decision mismatch, 0.05 when no AI second opinion is available, and 0.15 for malformed data.
