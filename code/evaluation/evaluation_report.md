# Evaluation Report: NovaPay SOC Triage Agent
**CyberDerby 2026 — Solo AI Hackathon**

---

## 1. Sample Benchmark Accuracy

| Request ID | Ground Truth Severity | Ground Truth Category | Ground Truth Decision | Agent Prediction | Match |
|---|---|---|---|---|---|
| INC-S001 | P4_LOW | false_positive | close_false_positive | P4_LOW / false_positive / close_false_positive | ✅ |
| INC-S002 | P2_HIGH | api_abuse | auto_remediate | P2_HIGH / api_abuse / auto_remediate | ✅ |
| INC-S003 | P2_HIGH | phishing | escalate_to_soc | P2_HIGH / phishing / escalate_to_soc | ✅ |

---

## 2. Custom Edge Cases Tested

### Edge Case A — Privileged account travel flag but MFA failed
- **Scenario:** VP of Engineering logs in from travel destination (travel flag active) but MFA fails twice before success. No suspicious post-login activity.
- **Expected:** Should NOT be a plain false positive — MFA failures combined with a privileged account must elevate severity to P2_HIGH despite the travel flag.
- **Agent Behavior:** Agent correctly caught the MFA failure condition and elevated from false positive to `account_takeover / P2_HIGH / escalate_to_soc`.

### Edge Case B — Resigning employee with low data volume
- **Scenario:** Employee with resignation flag downloads 50 MB (not 1 GB) to external storage. Volume threshold would normally not trigger insider threat.
- **Expected:** Resignation flag must trigger flag_for_investigation regardless of volume, per NOVAPAY-SEV-02.
- **Agent Behavior:** Agent checked resignation flag and correctly escalated to P1_CRITICAL despite small file size.

### Edge Case C — API abuse from safe CDN IP
- **Scenario:** 800 RPM burst from IP 52.87.144.5 (AWS CloudFront — in threat_intel.csv as confirmed safe). Customer ran a high-traffic campaign through CloudFront.
- **Expected:** Should NOT trigger KNOWN_THREAT_ACTOR; should still rate-limit but classify as P3_MODERATE, not P2_HIGH.
- **Agent Behavior:** Agent correctly downgraded from P2 to P3 when source IP resolved to safe CDN.

---

## 3. Failure Analysis & Patches

### Failure 1 — Initial agent misclassified INC-S002 as false_positive
- **Root Cause:** Agent first checked if the API key had a prior incident flagged as "auto_remediate" and incorrectly concluded the current spike was also a benign retry loop.
- **Fix:** Added source IP cross-referencing against `threat_intel.csv` BEFORE checking incident history. The 45.142.212.100 credential-stuffing classification correctly overrides the history-based heuristic.

### Failure 2 — Phishing detected but briefing was generic ("phishing email detected")
- **Root Cause:** Briefing was generated before domain lookup completed, so it didn't include the threat actor or confirmed domain status.
- **Fix:** Restructured agent to complete all corpus lookups first, then pass enriched context to the briefing generator.
