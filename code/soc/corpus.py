"""
Step 0 — Load the local knowledge corpus from data/.

Everything the agent "knows" comes from these four files. Nothing is fetched
from the internet. The corpus is loaded once at start-up and kept in memory.
"""

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent.parent   # repo root
DATA = BASE / "data"
DATASET = BASE / "dataset"


@dataclass
class Corpus:
    threat_ips: dict = field(default_factory=dict)        # ip -> row
    phishing_domains: dict = field(default_factory=dict)  # domain -> row
    employees: dict = field(default_factory=dict)         # EMP-xxx -> row
    history: dict = field(default_factory=dict)           # entity_id -> [rows]
    policy_text: str = ""
    policy_rule_codes: set = field(default_factory=set)   # e.g. NOVAPAY-CAT-01
    action_codes: set = field(default_factory=set)        # e.g. BLOCK_IP


def _read_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return [{k: (v or "").strip() for k, v in row.items()} for row in csv.DictReader(f)]


def load_corpus(data_dir: Path = DATA) -> Corpus:
    c = Corpus()

    # threat_intel.csv holds two tables: IPs first, then a marker row
    # "known_phishing_domains", then domains (re-using the ip_address column).
    in_domains = False
    for row in _read_csv(data_dir / "threat_intel.csv"):
        key = row.get("ip_address", "")
        if key == "known_phishing_domains":
            in_domains = True
            continue
        if not key:
            continue
        if in_domains:
            c.phishing_domains[key.lower()] = row
        else:
            c.threat_ips[key] = row

    for row in _read_csv(data_dir / "employee_registry.csv"):
        c.employees[row["employee_id"]] = row

    for row in _read_csv(data_dir / "incident_history.csv"):
        c.history.setdefault(row["entity_id"], []).append(row)

    c.policy_text = (data_dir / "pci_dss_policy.md").read_text(encoding="utf-8")
    # Rule codes and action codes are parsed FROM the handbook, not typed in by hand,
    # so if the policy changes the agent's allowed vocabulary changes with it.
    c.policy_rule_codes = set(re.findall(r"\[((?:NOVAPAY|PCI-DSS)-[A-Z0-9.\-]+)\]", c.policy_text))
    vocab = c.policy_text.split("Containment Action Vocabulary", 1)[-1]
    c.action_codes = set(re.findall(r"^\|\s*`([A-Z0-9_]+)`\s*\|", vocab, re.M))
    return c


def load_requests(path: Path) -> list[dict]:
    return _read_csv(path)
