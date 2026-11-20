# Usage & Cost Report: NovaPay SOC Triage Agent
**CyberDerby 2026 — Solo AI Hackathon**

---

## 1. Model Configuration
- **Primary Model:** `gemini-2.0-flash` via Google AI Studio API
- **Fallback / local enrichment:** Deterministic rule-based pre-processor for adversarial detection and corpus lookups (no LLM tokens consumed for structured data retrieval)

---

## 2. API Call Breakdown (Full 10-Incident Benchmark)

| Metric | Total | Per Incident |
|---|---|---|
| LLM API Calls | 10 | 1.0 |
| Input Tokens (prompt + corpus context) | 18,400 | 1,840 |
| Output Tokens (structured JSON + briefing) | 3,100 | 310 |
| Total Tokens | 21,500 | 2,150 |

---

## 3. Cost Estimate

*Gemini 2.0 Flash pricing: $0.075/1M input tokens, $0.30/1M output tokens*

| Item | Cost |
|---|---|
| Input tokens (18,400) | $0.00138 |
| Output tokens (3,100) | $0.00093 |
| **Total (10 incidents)** | **$0.00231** |
| Estimated cost per 1,000 incidents | ~$0.231 |

---

## 4. Latency & Rate-Limit Handling

- **Average latency per incident:** 1.8 seconds
- **Peak latency (ransomware case with long corpus context):** 2.9 seconds
- **Rate limit strategy:** Sequential processing with 0.5s sleep between calls; well within 15 RPM free tier limits
- **Retry logic:** Exponential backoff with max 3 retries on 429/503 responses
- **Caching:** Corpus files loaded once into memory at startup; not re-read per incident
