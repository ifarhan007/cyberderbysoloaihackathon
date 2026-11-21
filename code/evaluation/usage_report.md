# Usage & Cost Report: NovaPay SOC Triage Agent
**CyberDerby 2026 — Solo AI Hackathon**

Every number below was measured by the agent itself (`novapay_soc/llm.py` logs each API call) and saved in
`evaluation/usage_benchmark.json` and `evaluation/usage_samples.json`. Nothing is estimated unless
it says so.

---

## 1. Model configuration

| Setting | Value |
|---|---|
| SDK | official Google Gen AI SDK `google-genai` 3.6.1 |
| Primary model (`GEMINI_MODEL`) | `gemini-3.5-flash` (the API served it as `gemini-3.6-flash`) |
| Fallback chain (`GEMINI_FALLBACK_MODELS`) | `gemini-3.5-flash-lite`, `gemini-3.1-flash-lite` |
| Models that produced the final `output.csv` | `gemini-3.6-flash` for INC-3001 and INC-3002; `gemini-3.5-flash-lite` for INC-3003 to INC-3010 (primary hit its daily free quota, see §4) |
| Generation settings | temperature 0, `response_mime_type=application/json`, `response_schema` with enums |
| Calls per incident | 1 triage call; +1 repair call only if the briefing fails validation (0 needed in final run) |
| Corpus retrieval | deterministic Python lookups — no tokens spent on retrieval |
| Key handling | `GEMINI_API_KEY` from `.env` / environment, or injected by the cloud network proxy; never in code or `code.zip`. Test with `python agent.py --check-gemini` |

`gemini-2.5-flash` returned HTTP 404 ("no longer available to new users"), so it is not used.

---

## 2. API calls & tokens — final benchmark run (`python agent.py`, 10 incidents)

| Metric | Total | Per incident |
|---|---|---|
| API calls made | 11 | 1.1 |
| Successful calls | 10 | 1.0 |
| Failed calls (handled) | 1 (HTTP 429 daily quota on `gemini-3.5-flash`) | — |
| Input tokens | 28,047 | 2,805 |
| Output tokens | 4,554 | 455 |
| Thinking tokens | 4,885 (all from the two `gemini-3.6-flash` calls) | — |
| Briefing repair calls | 0 | 0 |
| Incidents handled by Gemini + guardrails | 10 / 10 | — |
| Incidents handled by deterministic fallback | 0 / 10 | — |
| Gemini agreement with policy engine (category, severity, decision) | 10 / 10 | — |

### Sample run (`python agent.py --samples`, 3 incidents)
4 calls (3 successful, 1× daily-quota 429 on the primary) · 8,246 input / 1,267 output tokens ·
all 3 handled by `gemini-3.5-flash-lite` · 1.59 s average latency · 5.6 s wall time.

### Earlier runs (kept for transparency)
* **Before the organiser updates**, with the first API key: the benchmark ran fully on
  `gemini-3.5-flash-lite` (12 calls, 10 successful, 26,987 input / 4,656 output tokens, 1.71 s average).
  Files: `evaluation/*_gemini_pre_update.*`. That key was later deleted for security.
* **Development runs** (raw REST, before the SDK migration) on `gemini-3.5-flash`: 10/10 successful,
  26,963 input / 5,077 output / 20,269 thinking tokens, 99.6 s. These and some test calls used up the
  first project's 20-requests/day quota.
* **Edge cases with Gemini** (`RUN_LLM_TESTS=1`): 12 tests in 20.4 s; per-call tokens were not recorded.
* **Briefing fix runs:** after finding wording errors (a computed "total", "actions executed",
  an unstated policy requirement), the prompt and checks were tightened and the benchmark was re-run.
  The intermediate run (12 calls, 26,987 input / 4,761 output tokens) is superseded by §2.

---

## 3. Cost

| Item | Value |
|---|---|
| Billing | **Free tier** (Google AI Studio key; no billing enabled) |
| Actual cost of the benchmark run | **$0.00** |
| Paid-tier equivalent | Not calculated: current per-token pricing for these models was not verified, so no number is given. Formula: `input_tokens × input_price + output_tokens × output_price` (per 1M tokens). |
| Free-tier limit observed | 20 requests / day / model (`quotaValue: 20` in the 429 response); per-minute limits and "high demand" 503s also occurred |
| Budget implication | One full benchmark is ~11 requests, so about one run per model per day; the 3-model fallback chain gives ~60 requests/day |

---

## 4. Latency & rate-limit handling

| Metric | Value (final run) |
|---|---|
| Average latency per successful call | 12.22 s overall; **1.80 s** on `gemini-3.5-flash-lite` (8 calls) |
| Slowest calls | 90.22 s and 17.66 s on `gemini-3.6-flash` (thinking model, high demand) |
| Wall time, 10 incidents (sequential) | 122.9 s |
| Wall time, 3 samples | 5.6 s |

**Retry / fallback strategy** (`novapay_soc/llm.py`, `novapay_soc/pipeline.py`):
1. Calls are **sequential**, one incident at a time (free-tier friendly).
2. Transient errors (429 per-minute, 500/503 "high demand", 504, timeouts, network errors): up to 3
   attempts per model with 5 s → 10 s backoff. The SDK's own retries are disabled so behaviour is explicit.
3. Daily quota exhausted (`429 …PerDay…`) or model unavailable (`404`/`400`): that model is skipped for the
   rest of the run and the next model in `GEMINI_FALLBACK_MODELS` is used. Observed in this run at INC-3003.
4. Invalid key (`401/403`) or every model failing: the incident is triaged by the **deterministic policy
   engine**; the run continues and the row's trace records `engine: deterministic_fallback` with the reason.
   The agent never invents an AI response.
5. Request timeout: 120 s per call.
6. The corpus is loaded once at start-up; the policy handbook is sent as the system instruction with each
   call (most of the ≈2.8k input tokens per incident; estimate, not separately measured).
