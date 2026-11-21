# Usage & Cost Report: NovaPay SOC Triage Agent
**CyberDerby 2026 — Solo AI Hackathon**

Every number below was measured by the agent itself (`soc/llm.py` logs each API call) and saved in
`evaluation/usage_benchmark.json` and `evaluation/usage_samples.json`. Nothing is estimated unless
it says so.

---

## 1. Model configuration

| Setting | Value |
|---|---|
| SDK | official Google Gen AI SDK `google-genai` 3.6.1 |
| Primary model (`GEMINI_MODEL`) | `gemini-3.5-flash` |
| Fallback chain (`GEMINI_FALLBACK_MODELS`) | `gemini-3.5-flash-lite`, `gemini-3.1-flash-lite` |
| **Model that produced the final output.csv** | **`gemini-3.5-flash-lite`** (primary was over its daily free quota — see §4) |
| Generation settings | temperature 0, `response_mime_type=application/json`, `response_schema` with enums |
| Calls per incident | 1 triage call; +1 repair call only if the briefing fails validation (0 needed in final run) |
| Corpus retrieval | deterministic Python lookups — no tokens spent on retrieval |

Models were checked against the key's `models.list` endpoint. `gemini-2.5-flash` returned HTTP 404
("no longer available to new users"), so it is not used.

---

## 2. API calls & tokens — final benchmark run (`python agent.py`, 10 incidents)

| Metric | Total | Per incident |
|---|---|---|
| API calls made | 12 | 1.2 |
| Successful calls | 10 | 1.0 |
| Failed calls (HTTP 429, then handled) | 2 | — |
| Input tokens | 26,987 | 2,699 |
| Output tokens | 4,656 | 466 |
| Thinking tokens | 0 (flash-lite reported none) | 0 |
| Briefing repair calls | 0 | 0 |
| Incidents handled by Gemini + guardrails | 10 / 10 | — |
| Incidents handled by deterministic fallback | 0 / 10 | — |

The 2 failed calls: one `429 GenerateRequestsPerDayPerProjectPerModel-FreeTier` on `gemini-3.5-flash`
(daily cap of 20 reached during development; the model was then skipped for the rest of the run), and
one per-minute `429` on `gemini-3.5-flash-lite` for INC-3010, which succeeded after a 5 s backoff.

### Sample run (`python agent.py --samples`, 3 incidents)
4 calls (3 successful, 1× daily-quota 429 on the primary) · 7,929 input / 1,210 output tokens ·
all 3 incidents handled by `gemini-3.5-flash-lite`.

### Edge-case run with Gemini (`RUN_LLM_TESTS=1`)
12 tests in 20.4 s. Per-call tokens were **not recorded** for this run (the test harness does not
write a usage file).

### Earlier development runs (same day, superseded)
Before the SDK migration, a raw-REST version ran the full benchmark on `gemini-3.5-flash` (served as
`gemini-3.6-flash`): 10/10 successful calls, 26,963 input / 5,077 output / 20,269 thinking tokens,
99.6 s wall time. Those runs, plus ~10 test calls, used up the 20-requests/day free quota of
`gemini-3.5-flash`.

---

## 3. Cost

| Item | Value |
|---|---|
| Billing | **Free tier** (Google AI Studio key; no billing enabled by me) |
| Actual cost of the benchmark run | **$0.00** |
| Paid-tier equivalent | Not calculated: I did not verify current per-token pricing for `gemini-3.5-flash-lite`, so no number is given. Formula: `26,987 × input_price + 4,656 × output_price` per 1M tokens. |
| Free-tier limit observed | 20 requests / day / model (`quotaValue: 20` in the 429 response); a per-minute limit also exists (one 429 observed) |
| Budget implication | One full benchmark run uses about 10–12 requests, so about one run per model per day; the fallback chain gives 3 models ≈ 60 requests/day |

---

## 4. Latency & rate-limit handling

| Metric | Value (final run) |
|---|---|
| Average Gemini latency per successful call | **1.71 s** |
| Max latency | 1.98 s |
| Wall time, 10 incidents (sequential) | 23.0 s |
| Wall time, 3 samples | 6.6 s |
| Development run on `gemini-3.5-flash` (thinking model) | ~22 s per call, 99.6 s total |

**Retry / fallback strategy** (`soc/llm.py`, `soc/pipeline.py`):
1. Calls are **sequential**, one incident at a time (free-tier friendly).
2. Transient errors (HTTP 429 per-minute, 500/503 "high demand", 504, timeouts, network errors):
   up to 3 attempts per model with backoff of 5 s, then 10 s. The SDK's own retries are turned off
   so the behaviour is explicit.
3. Daily quota exhausted (`429 …PerDay…`) or model not available (`404`/`400`): the model is
   skipped and the next model in `GEMINI_FALLBACK_MODELS` is tried.
4. Invalid API key (`401/403`) or all models failed: the incident is triaged by the **deterministic
   policy engine**, the run continues, and the trace records `engine: deterministic_fallback` with
   the reason. The agent never invents an AI response.
5. Request timeout: 120 s per call.
6. The corpus is loaded once at start-up; the policy handbook is sent as the system instruction
   with each call (estimated as most of the ≈2.7k measured input tokens per incident).
