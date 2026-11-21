# NovaPay SOC Triage Agent — how it works

A hybrid AI agent: **deterministic corpus lookups + policy rules + Gemini reasoning + guardrails**.
It only *recommends* containment actions (simulation mode); it never touches real accounts or systems.

## Pipeline (one incident)

```
requests.csv row
   │
   ▼
[1] novapay_soc/evidence.py  — parse raw_signal_data safely, look up every IP in threat_intel.csv,
   │                   sender domain in the phishing list, employee in the registry
   │                   (scope, IP range, local hours, resignation, travel), incident history
   │                   (fraud flag within 90 days), detect prompt-injection phrases.
   ▼
[2] novapay_soc/policy.py    — encodes NOVAPAY-CAT-01..10 and SEV-01/02 as rules. Gives a baseline
   │                   category/severity and says whether the match is DECISIVE.
   ▼
[3] novapay_soc/llm.py       — Gemini (official google-genai SDK) gets the policy handbook, the verified
   │                   evidence, and the description wrapped in <untrusted_description>.
   │                   It must answer in a JSON schema (enums are enforced by the API).
   ▼
[4] novapay_soc/pipeline.py  — guardrails:
   │   • decisive rule match  → category/severity locked; LLM is a second opinion (affects confidence)
   │   • inconclusive         → LLM classification used, but never auto-close / auto-remediate
   │   • triage_decision always = the policy's mandatory decision for the category
   │   • action codes / rule codes must exist in the handbook; invented IPs/IDs are dropped
   │   • Gemini may only ADD low-impact steps (alert, notify CISO, monitor, preserve forensics);
   │     freezing, revoking, blocking, isolating, MFA resets must come from a policy rule
   │   • briefings: no invented IDs/IPs/amounts, no computed totals, no "executed" claims
   │   • briefing must be 30–70 words and mention only IDs/IPs in the evidence (1 repair call,
   │     then deterministic briefing)
   │   • Gemini down / quota exhausted → deterministic engine, run continues
   ▼
output.csv row  +  evaluation/trace_*.json (evidence, rules, LLM reasoning, guardrail actions, engine)
```

## Why hybrid?
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
python app.py
```

Safe demo run (never touches the submitted `output.csv` or its evidence):
```bat
python agent.py --output demo\demo.csv
```

**In PyCharm / VS Code:** don't press ▶ on an empty run configuration ("Python script path must be set").
Use the editor's terminal and the commands above, or right-click `app.py` / `evaluate.py` → Run, with the
working directory set to the `code` folder.

`notepad .env` → paste your key after `GEMINI_API_KEY=` and save.

Optional: `set RUN_LLM_TESTS=1` before the unittest command runs the edge cases through Gemini too.
`python agent.py --offline` runs without any API calls (deterministic engine only).

## Gemini API key

The agent reads `GEMINI_API_KEY`. The key is never written in the source code, never sent to the
browser, and never included in `code.zip`.

**On your own PC (Windows):**
```bat
copy .env.example .env
notepad .env
```
Paste the key after `GEMINI_API_KEY=` and save. On a shared or lab PC, set it only for the current window
instead (it disappears when the window closes):
```bat
set GEMINI_API_KEY=your_key_here
```

**In the Claude Code cloud environment:** add a *Network secret* for host
`generativelanguage.googleapis.com` with header `x-goog-api-key`. The proxy inserts the real key, so `.env`
only holds a placeholder.

**Check that it works:**
```bat
python agent.py --check-gemini
```
Expected: `[OK] gemini-3.5-flash works ... Gemini is ready.` If every model says "API key not valid",
the key is wrong or was deleted. If it says "quota", the free daily limit is used up. In both cases the
agent still runs using the rules-only fallback.

## Triage console (web UI)

```bat
python app.py
```
Then open http://127.0.0.1:5000 in a browser. Press Ctrl+C in the terminal to stop it.

| Tab | What it shows |
|---|---|
| Incident Queue | All 10 incidents sorted by severity, with KPIs. Each incident shows: briefing, decision pipeline (evidence → policy → Gemini → guardrails), verified evidence, Gemini's reasoning and agreement, guardrail log, containment timeline, flags and citations (hover a citation for its handbook title), and the original report with injection phrases highlighted |
| Sample Validation | The 3 labelled samples against the ground truth |
| Triage New Incident | Type an incident or load one: benchmark, samples, or adversarial demos (injection inside ransomware, travel flag hiding an account takeover, safe CDN burst) |
| Engine & Usage | Model, API calls, tokens, latency, engine per incident, fallback chain; re-run the benchmark |

* The API key stays on the server; the page only learns *whether* a key is set.
* The server listens on 127.0.0.1 only, and request bodies are limited to 64 KB and validated.
* All incident text is rendered as plain text, so injected HTML/JS can't execute.
* The console never overwrites the submitted `output.csv`; re-runs go to `evaluation/ui_benchmark.csv`.

## Files
| File | Role |
|---|---|
| `agent.py` | CLI entry point; writes `../output.csv`, traces and usage logs |
| `novapay_soc/corpus.py` | loads data/ once; parses rule codes + action codes from the handbook |
| `novapay_soc/evidence.py` | per-incident evidence gathering and injection detection |
| `novapay_soc/policy.py` | policy rules, containment plans, risk flags, citations |
| `novapay_soc/llm.py` | Gemini client: JSON schema, retries, model fallback, quota circuit breaker |
| `novapay_soc/pipeline.py` | orchestration, guardrails, confidence calibration |
| `evaluate.py` | schema validator + sample scoring (organiser's script, extended) |
| `tests/test_edge_cases.py` | custom edge cases + regression tests for starter-code bugs |
| `package_submission.py` | builds `../code.zip` (excludes .env, venv, caches, data) |
| `app.py`, `web/` | local triage console (Flask backend + HTML/CSS/JS, no internet needed) |

## Design decisions & FAQ

**Q: Where is the AI?** `novapay_soc/llm.py` sends Gemini the handbook, the verified evidence and the
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
