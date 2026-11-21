# 🏦 CyberDerby 2026 — NovaPay SOC Challenge

> **Solo AI Hackathon** | Hosted by UITC, UCSI University Bangladesh Campus  
> **Sprint:** Thursday, 19 November 2026 · 10:00 AM – 03:00 PM  
> **Venue:** 13th Floor Computer Lab, UCSI University Bangladesh Campus  
> **Official AI Partners:** MindSpark · Sigmind

---

## 🎯 The Challenge

You are an AI engineer embedded in the **Security Operations Center (SOC) of NovaPay Bank**.

Ten security incidents just hit the queue. Human analysts are overwhelmed. Your mission: build an **autonomous AI agent** that reads NovaPay's internal policy corpus and triages all 10 incidents — classifying each by severity, category, and containment plan — with zero human intervention.

Read the full brief → [`problem_statement.md`](problem_statement.md)

---

## 📦 What's in This Repo

```
cyberderbysoloaihackathon/
├── problem_statement.md          ← Full challenge specification (read this first)
├── README.md                     ← You are here
│
├── data/                         ← Local corpus (your agent reads these)
│   ├── pci_dss_policy.md         ← NovaPay security policy & containment vocabulary
│   ├── threat_intel.csv          ← Known malicious IPs & phishing domains
│   ├── employee_registry.csv     ← Employee roles, access tiers, travel/resignation flags
│   └── incident_history.csv      ← Historical incidents & active fraud flags
│
├── dataset/
│   ├── requests.csv              ← 10 benchmark incidents (your agent processes these)
│   ├── sample_requests.csv       ← 3 labelled examples to test your agent
│   └── sample_output.csv         ← Ground truth for the 3 sample cases
│
└── code/
    ├── agent.py                  ← Starter agent — modify this
    ├── evaluate.py               ← Schema validator & sample case scorer
    ├── requirements.txt          ← Python dependencies
    ├── .env.example              ← API key template (copy to .env)
    └── evaluation/
        ├── evaluation_report.md  ← Fill this in before submission
        └── usage_report.md       ← Fill this in before submission
```

---

## ⚡ Quickstart

```bash
# 1. Follow the organizer on GitHub (required)
#    https://github.com/luminancexe

# 2. Clone this repo
git clone https://github.com/luminancexe/cyberderbysoloaihackathon.git
cd cyberderbysoloaihackathon/code

# 3. Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux

# 4. Install dependencies
pip install -r requirements.txt

# 5. Add your API key
cp .env.example .env
# Open .env and add your key (Gemini / OpenAI / Claude / etc.)

# 6. Run your agent
python agent.py
# → generates ../output.csv

# 7. Validate your output
python evaluate.py
# → must show: Schema valid: YES | Output rows: 10/10
```

---

## 📤 What to Submit (by 03:00 PM)

Upload **3 files** to the Devpost submission portal before the 3:00 PM code freeze:

| # | File | What it is |
|:---:|---|---|
| 1 | `code.zip` | Zip of your `code/` folder only |
| 2 | `output.csv` | Your agent's triage decisions (10 rows) |
| 3 | `log.txt` | Your full AI session chat transcript |

> **⚠️ code.zip must exclude:** `venv/`, `.venv/`, `__pycache__/`, `node_modules/`, `data/`, `dataset/`

---

## 🏆 Scoring (100 Points)

| Weight | Criterion | Focus |
|:---:|---|---|
| 30% | **Accuracy & Schema** | Exact `output.csv` schema + correct triage decisions |
| 30% | **Eval & Pipeline Logic** | Clean `agent.py`, working `evaluate.py`, thorough reports |
| 20% | **AI Innovation** | LLMs, structured prompting, multi-step reasoning |
| 20% | **Viva & Log Audit** | Live code defense + authentic `log.txt` trace |

---

## 🛠️ Rules at a Glance

- ⭐ **Follow the organizer on GitHub** — [github.com/luminancexe](https://github.com/luminancexe) *(required before cloning)*
- 🔒 **Solo only** — no teams, no sharing prompts or code during the sprint
- 📁 **Local corpus only** — your agent reads from `data/` only, no live web lookups
- 🚫 **No hardcoded answers** — all predictions must come from reproducible agent execution
- 🔑 **API keys in `.env`** — never hardcode credentials in source files
- ⏱️ **3:00 PM cutoff is strict** — late submissions are not accepted
- 🎙️ **Viva is mandatory** — you must defend every line of your code live

Full rules → [`problem_statement.md`](problem_statement.md)

---

## 🤖 Allowed AI Platforms

You are free to use any major AI platform or open-source model:

**Cloud:** Google Gemini / AI Studio · OpenAI GPT · Anthropic Claude · Groq · OpenRouter  
**Open-source:** Hugging Face · Ollama · Llama · Qwen · DeepSeek · Mistral

---

## 🎖️ Award Ceremony

Rankings announced at the **Grand Award Ceremony**:  
📅 **Tuesday, 24 November 2026 · 03:35 PM – 05:00 PM**  
📍 12th Floor Hall, UCSI University Bangladesh Campus

**Prizes:** Champion · 1st Runner-Up · 2nd Runner-Up · Accredited Certificates · Prize Money  
**Bonus:** Top engineers earn direct internship/recruitment visibility with MindSpark & Sigmind

---

## 📬 Contact

| Role | Name |
|---|---|
| President | Abdullah Al Noman |
| Vice President | Sharhee Saad Imam |
| General Secretary | Farhana Akter |

**Email:** uitc.bd@ucsiuniversity.edu.my  
**Facebook:** fb.com/uitcbd · **Instagram:** @uitc.bd · **LinkedIn:** UITC UCSI BD

---

<div align="center">
  <sub>Organized by UCSI Information Technology Club (UITC) · UCSI University Bangladesh Campus</sub>
</div>
