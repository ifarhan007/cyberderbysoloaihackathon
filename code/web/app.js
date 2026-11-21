/* NovaPay SOC Triage Console — vanilla JS, no external dependencies.
   All text is inserted with textContent (never innerHTML), so incident data can't inject markup. */
"use strict";

const SEV = {
  P1_CRITICAL: { label: "P1 Critical", short: "P1", color: "var(--p1)", rank: 0 },
  P2_HIGH: { label: "P2 High", short: "P2", color: "var(--p2)", rank: 1 },
  P3_MODERATE: { label: "P3 Moderate", short: "P3", color: "var(--p3)", rank: 2 },
  P4_LOW: { label: "P4 Low", short: "P4", color: "var(--p4)", rank: 3 },
};
const state = { status: null, data: null, selected: null, sev: "ALL", q: "", set: "benchmark", templates: null };

// ── tiny DOM helper ──────────────────────────────────────────────────────
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style") el.style.cssText = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const $ = (s) => document.querySelector(s);
const label = (s) => String(s || "").replace(/_/g, " ");
const pct = (x) => `${Math.round(Number(x) * 100)}%`;
function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.classList.add("show");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove("show"), 2600);
}
async function api(path, opts) {
  const r = await fetch(path, opts);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
  return body;
}
function parseJSON(s, fallback) { try { return JSON.parse(s); } catch { return fallback; } }
const isAI = (t) => (t && t.engine) === "gemini+guardrails";

// ── Theme ────────────────────────────────────────────────────────────────
(function theme() {
  let saved = null;
  try { saved = localStorage.getItem("soc-theme"); } catch {}
  if (saved) document.documentElement.dataset.theme = saved;
  $("#themeBtn").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("soc-theme", next); } catch {}
  });
})();

// ── Tabs ─────────────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${b.dataset.view}`));
  if (b.dataset.view === "samples") loadSamples();
  if (b.dataset.view === "usage") renderUsage();
}));

// ── Status bar ───────────────────────────────────────────────────────────
function renderStatus() {
  const s = state.status, c = s.corpus;
  $("#status").replaceChildren(
    h("span", { class: `pill ${s.key_configured ? "on" : "off"}`, title: s.models.join(" → ") },
      h("span", { class: "dot" }), s.key_configured ? `Gemini key set · ${s.models[0]}` : "Gemini key not set · rules-only"),
    h("span", { class: "pill corpus", title: "Local corpus loaded from data/" },
      `${c.threat_ips} IOCs · ${c.phishing_domains} domains · ${c.employees} staff · ${c.history} history · ${c.rules} rules`),
  );
  const t = $("#useLlm");
  t.checked = s.key_configured; t.disabled = !s.key_configured;
  $("#useLlmLabel").textContent = s.key_configured ? "Use Gemini" : "Gemini unavailable (no key)";
  $("#datasetSel").querySelector('[value="ui"]').disabled = !s.has_ui_run;
}

// ── Queue ────────────────────────────────────────────────────────────────
async function loadQueue() {
  $("#detail").replaceChildren(h("div", { class: "skeleton" }));
  state.data = await api(`/api/results?set=${state.set}`);
  state.data.items.sort((a, b) => SEV[a.output.severity].rank - SEV[b.output.severity].rank
    || a.output.request_id.localeCompare(b.output.request_id));
  renderKpis();
  renderQueue();
  const first = state.data.items.find((i) => i.output.request_id === state.selected) || state.data.items[0];
  if (first) select(first.output.request_id); else $("#detail").replaceChildren(h("div", { class: "empty" }, "No results yet."));
}

function renderKpis() {
  const items = state.data.items, n = items.length || 1;
  const count = (sev) => items.filter((i) => i.output.severity === sev).length;
  const ai = items.filter((i) => isAI(i.trace)).length;
  const agreeAll = items.filter((i) => i.trace.agreement && Object.values(i.trace.agreement).every(Boolean)).length;
  const guard = items.filter((i) => (i.trace.guardrails || []).length).length;
  const avg = items.reduce((s, i) => s + Number(i.output.confidence_score), 0) / n;
  const closed = items.filter((i) => i.output.triage_decision === "close_false_positive").length;
  const kpi = (lab, val, sub, color, extra) => h("div", { class: "kpi", style: `--kc:${color}` },
    h("div", { class: "label" }, lab), h("div", { class: "value" }, val), h("div", { class: "sub" }, sub), extra);
  const bar = h("div", { class: "sevbar" }, ...Object.keys(SEV).map((k) =>
    h("span", { style: `width:${(count(k) / n) * 100}%;background:${SEV[k].color}`, title: `${SEV[k].label}: ${count(k)}` })));
  $("#kpis").replaceChildren(
    kpi("Incidents", items.length, `${count("P1_CRITICAL")} critical · ${count("P2_HIGH")} high`, "var(--accent)", bar),
    kpi("Critical (P1)", count("P1_CRITICAL"), "15-minute SLA", "var(--p1)"),
    kpi("Closed as FP", closed, "fully explained by corpus", "var(--p4)"),
    kpi("Gemini-handled", `${ai}/${items.length}`, `${agreeAll} full agreement with policy`, "var(--ai)"),
    kpi("Guardrail actions", guard, "incidents with an override", "var(--warn)"),
    kpi("Avg confidence", pct(avg), "calibrated score", "var(--accent)"),
  );
}

function renderQueue() {
  const q = state.q.toLowerCase();
  const items = state.data.items.filter((i) =>
    (state.sev === "ALL" || i.output.severity === state.sev) &&
    (!q || [i.output.request_id, i.incident.affected_entity_id, i.output.incident_category, i.output.triage_decision, i.incident.source_system]
      .join(" ").toLowerCase().includes(q)));
  $("#queue").replaceChildren(...(items.length ? items.map((i) => {
    const o = i.output, s = SEV[o.severity];
    return h("button", { class: `qitem ${o.request_id === state.selected ? "active" : ""}`, style: `--sc:${s.color}`,
      onclick: () => { state.userPicked = true; select(o.request_id); }, "aria-label": `${o.request_id} ${s.label} ${label(o.incident_category)}` },
      h("span", { class: "stripe" }),
      h("div", {},
        h("div", { class: "top" }, h("span", { class: "id" }, o.request_id),
          h("span", { class: "badge sev", style: `--sc:${s.color}` }, s.short),
          (i.trace.guardrails || []).length ? h("span", { class: "badge", title: "Guardrail intervened" }, "⚑") : null),
        h("div", { class: "cat" }, label(o.incident_category)),
        h("div", { class: "meta" }, `${i.incident.affected_entity_id} · ${label(o.triage_decision)}`)),
      h("div", { class: "right" },
        h("span", { title: isAI(i.trace) ? "Gemini + guardrails" : "Deterministic fallback" },
          h("span", { class: `engine-dot ${isAI(i.trace) ? "ai" : "rules"}` })),
        h("div", { class: "minibar", title: `Confidence ${o.confidence_score}` },
          h("span", { style: `width:${pct(o.confidence_score)}` })),
        h("span", { class: "meta" }, o.estimated_containment_window)));
  }) : [h("div", { class: "empty" }, "No incidents match the filter.")]));
}

function select(id) {
  state.selected = id;
  document.querySelectorAll(".qitem").forEach((el) => el.classList.toggle("active", el.querySelector(".id")?.textContent === id));
  const item = state.data.items.find((i) => i.output.request_id === id);
  if (item) {
    $("#detail").replaceChildren(...renderDetail(item));
    const top = $("#detail").getBoundingClientRect().top;
    const stacked = window.matchMedia("(max-width: 900px)").matches;
    if (top < 0 || (stacked && state.userPicked)) window.scrollBy({ top: top - 80, behavior: "smooth" });
  }
}

$("#sevFilter").addEventListener("click", (e) => {
  const b = e.target.closest(".seg-btn"); if (!b) return;
  state.sev = b.dataset.sev;
  document.querySelectorAll("#sevFilter .seg-btn").forEach((x) => x.classList.toggle("active", x === b));
  renderQueue();
});
$("#search").addEventListener("input", (e) => { state.q = e.target.value; renderQueue(); });
$("#datasetSel").addEventListener("change", (e) => { state.set = e.target.value; loadQueue().catch((err) => toast(err.message)); });

// ── Detail view (shared by queue, samples, new triage) ───────────────────
function ring(conf, color) {
  const r = 38, c = 2 * Math.PI * r, v = Math.max(0, Math.min(1, Number(conf)));
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 92 92");
  svg.innerHTML = `<circle cx="46" cy="46" r="${r}" fill="none" stroke="var(--panel-3)" stroke-width="8"/>` +
    `<circle cx="46" cy="46" r="${r}" fill="none" stroke="${color}" stroke-width="8" stroke-linecap="round" stroke-dasharray="${c * v} ${c}"/>`;
  return h("div", { class: "ring", title: "Calibrated confidence" }, svg,
    h("div", { class: "val" }, h("div", {}, Number(conf).toFixed(2), h("small", {}, "confidence"))));
}

function evidenceTag(note) {
  const n = note.toLowerCase();
  if (n.includes("matches threat intel") || n.includes("confirmed phishing")) return ["intel", "THREAT INTEL"];
  if (n.includes("listed as safe") || n.includes("not in the known phishing")) return ["safe", "INTEL · CLEAR"];
  if (n.startsWith("registry") || n.includes("approved scope") || n.includes("usual range") || n.includes("usual hours")) return ["registry", "REGISTRY"];
  if (n.startsWith("history") || n.includes("fraud flag")) return ["history", "HISTORY"];
  if (n.includes("instruction-like") || n.startsWith("tampering")) return ["inject", "INJECTION"];
  return ["signal", "SIGNAL"];
}

function highlight(text, phrases) {
  const frag = document.createDocumentFragment();
  const ps = (phrases || []).filter(Boolean);
  if (!ps.length) { frag.append(text); return frag; }
  const esc = ps.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).sort((a, b) => b.length - a.length);
  const rx = new RegExp(`(${esc.join("|")})`, "gi");
  let last = 0;
  for (const m of text.matchAll(rx)) {
    frag.append(text.slice(last, m.index), h("mark", { title: "Detected manipulation phrase — ignored by the agent" }, m[0]));
    last = m.index + m[0].length;
  }
  frag.append(text.slice(last));
  return frag;
}

function renderDetail(item, opts = {}) {
  const { incident: inc, output: o, trace: t } = item;
  const s = SEV[o.severity];
  const rules = state.status?.rule_titles || {}, acts = state.status?.action_desc || {};
  const plan = parseJSON(o.containment_actions, []);
  const llm = t.llm, ag = t.agreement, guards = t.guardrails || [], re = t.rule_engine || {};
  const raw = parseJSON(inc.raw_signal_data, null);

  const hero = h("section", { class: "card hero", style: `--sc:${s.color}` },
    h("div", {},
      h("div", { class: "hero-id" }, h("span", {}, o.request_id), h("span", {}, inc.affected_entity_id),
        h("span", {}, inc.source_system), h("span", {}, (inc.timestamp || "").replace("T", " ").replace("Z", " UTC"))),
      h("div", { class: "hero-title" }, label(o.incident_category)),
      h("div", { class: "badges" },
        h("span", { class: "badge sev", style: `--sc:${s.color}` }, s.label),
        h("span", { class: "badge mono" }, o.triage_decision),
        h("span", { class: "badge" }, `⏱ ${o.estimated_containment_window}`),
        h("span", { class: `badge ${isAI(t) ? "ai" : ""}` }, isAI(t) ? "✦ Gemini + guardrails" : "Deterministic fallback"),
        opts.elapsed != null ? h("span", { class: "badge" }, `${opts.elapsed}s`) : null)),
    ring(o.confidence_score, s.color));

  const brief = h("section", { class: "card" },
    h("div", { class: "card-title" }, "Analyst briefing", h("span", { class: "count" }, `${o.analyst_briefing.split(/\s+/).filter(Boolean).length} words`)),
    h("div", { class: "briefing" }, o.analyst_briefing),
    h("div", { class: "briefing-foot" }, isAI(t) ? "Written by Gemini from verified evidence; checked for length and invented identifiers." :
      "Generated deterministically from verified evidence."));

  const agreeAll = ag && Object.values(ag).every(Boolean);
  const pipeline = h("section", { class: "card" },
    h("div", { class: "card-title" }, "Decision pipeline"),
    h("div", { class: "pipeline" },
      h("div", { class: "stage" }, h("div", { class: "n" }, "1 · Evidence"), h("div", { class: "t" }, `${(t.evidence || []).length} facts`),
        h("div", { class: "s" }, "Corpus lookups: threat intel, registry, history, telemetry")),
      h("div", { class: "stage" }, h("div", { class: "n" }, "2 · Policy engine"), h("div", { class: "t" }, `${label(re.category)} · ${SEV[re.severity]?.short || ""}`),
        h("div", { class: "s" }, re.decisive ? "Decisive match — decision locked" : "Inconclusive — AI reasoning needed")),
      h("div", { class: `stage ${llm ? "ai" : ""}` }, h("div", { class: "n" }, "3 · Gemini"),
        h("div", { class: "t" }, llm ? `${label(llm.incident_category)} · ${SEV[llm.severity]?.short || ""}` : "Not used"),
        h("div", { class: "s" }, llm ? (agreeAll ? "Agrees with policy on all fields" : "Disagrees — see guardrails") : (t.llm_error || "Offline / fallback mode"))),
      h("div", { class: `stage ${guards.length ? "warn" : ""}` }, h("div", { class: "n" }, "4 · Guardrails"),
        h("div", { class: "t" }, guards.length ? `${guards.length} intervention${guards.length > 1 ? "s" : ""}` : "No overrides"),
        h("div", { class: "s" }, "Enums, action codes, citations, briefing, mandatory decision"))));

  const evidence = h("section", { class: "card" },
    h("div", { class: "card-title" }, "Verified evidence", h("span", { class: "count" }, `${(t.evidence || []).length} items`)),
    h("ul", { class: "ev" }, ...(t.evidence || []).map((n) => {
      const [cls, txt] = evidenceTag(n);
      return h("li", {}, h("span", { class: `tag ${cls}` }, txt), h("span", {}, n));
    })));

  const policyCard = h("section", { class: "card" },
    h("div", { class: "card-title" }, "Policy engine", h("span", { class: "count" }, re.decisive ? "decisive" : "inconclusive")),
    h("ul", { class: "why" }, ...(re.why || []).map((w) => h("li", {}, w))));

  const fields = [["Category", "incident_category"], ["Severity", "severity"], ["Decision", "triage_decision"]];
  const gemCard = h("section", { class: "card" },
    h("div", { class: "card-title" }, "✦ Gemini reasoning"),
    llm ? [
      h("div", { class: "agree" },
        h("div", { class: "row head" }, h("span", {}, "Field"), h("span", {}, "Gemini"), h("span", {}, "Final"), h("span", {})),
        ...fields.map(([lab, k]) => {
          const okk = llm[k] === o[k];
          return h("div", { class: "row" }, h("span", { class: "hint" }, lab), h("code", {}, llm[k]), h("code", {}, o[k]),
            h("span", { class: okk ? "ok" : "bad" }, okk ? "✓" : "✗"));
        })),
      llm.reasoning ? h("div", { class: "reason" }, llm.reasoning) : null,
      llm.description_trustworthy === false ? h("div", { class: "reason" }, "Gemini judged the description untrustworthy.") : null,
    ] : h("div", { class: "reason" }, t.llm_error ? `Not used: ${t.llm_error}` : "Not used (offline mode)."));

  const guardCard = h("section", { class: "card" },
    h("div", { class: "card-title" }, "Guardrail log"),
    guards.length ? h("ul", { class: "guard" }, ...guards.map((g) => h("li", {}, g)))
      : h("ul", { class: "guard none" }, h("li", {}, "No interventions — the output passed every check unchanged.")));

  const planCard = h("section", { class: "card" },
    h("div", { class: "card-title" }, "Containment plan", h("span", { class: "count" }, `${plan.length} ordered steps`)),
    h("ol", { class: "timeline" }, ...plan.map((p) => {
      const extra = Object.entries(p).filter(([k]) => !["step", "action", "target"].includes(k));
      return h("li", {}, h("span", { class: "num" }, p.step),
        h("div", { class: "act" }, p.action), h("div", { class: "desc" }, acts[p.action] || ""),
        p.target ? h("div", { class: "tgt" }, "Target ", h("code", {}, p.target)) : null,
        ...extra.map(([k, v]) => h("div", { class: "tgt" }, `${label(k)}: `, h("code", {}, String(v)))));
    })));

  const flags = o.risk_flags.split("|");
  const metaCard = h("section", { class: "card" },
    h("div", { class: "sub-h" }, "Risk flags"),
    h("div", { class: "chips" }, ...flags.map((f) => h("span", { class: `chip flag ${f === "NONE" ? "none" : ""}` }, f))),
    h("div", { class: "sub-h" }, "Policy citations"),
    h("div", { class: "chips" }, ...o.policy_citations.split(";").map((c) => h("span", { class: "chip", title: rules[c] || "" }, c))),
    h("div", { class: "sub-h" }, "Affected systems"),
    h("div", { class: "chips" }, ...o.affected_systems.split("|").map((c) => h("span", { class: "chip" }, c))));

  const truth = opts.truth;
  const truthCard = truth ? h("section", { class: "card" },
    h("div", { class: "card-title" }, "Ground truth comparison"),
    h("div", { class: "agree" },
      h("div", { class: "row head" }, h("span", {}, "Field"), h("span", {}, "Ground truth"), h("span", {}, "Agent"), h("span", {})),
      ...[["Severity", "severity"], ["Category", "incident_category"], ["Decision", "triage_decision"], ["Window", "estimated_containment_window"], ["Flags", "risk_flags"]]
        .map(([lab, k]) => h("div", { class: "row" }, h("span", { class: "hint" }, lab), h("code", {}, truth[k]), h("code", {}, o[k]),
          h("span", { class: truth[k] === o[k] ? "ok" : "bad" }, truth[k] === o[k] ? "✓" : "✗"))))) : null;

  const source = h("section", { class: "card" },
    h("div", { class: "card-title" }, "Source incident"),
    h("div", { class: "untrusted-label" }, "⚠ UNTRUSTED REPORTER TEXT — never executed as instructions"),
    h("div", { class: "untrusted" }, highlight(inc.incident_description || "", t.injection_phrases)),
    h("div", { class: "sub-h" }, "Raw signal data"),
    h("pre", { class: "json" }, raw ? JSON.stringify(raw, null, 2) : (inc.raw_signal_data || "(empty)")));

  return [hero, truthCard, brief, pipeline, h("div", { class: "grid2" }, evidence, h("div", {}, policyCard, gemCard, guardCard)),
    h("div", { class: "grid2" }, planCard, metaCard), source].filter(Boolean);
}

// ── Samples ──────────────────────────────────────────────────────────────
let samplesLoaded = false;
async function loadSamples() {
  if (samplesLoaded) return;
  const d = await api("/api/results?set=samples");
  samplesLoaded = true;
  const fields = [["Severity", "severity"], ["Category", "incident_category"], ["Decision", "triage_decision"], ["Window", "estimated_containment_window"]];
  const pass = d.items.filter((i) => fields.slice(0, 3).every(([, k]) => d.truth[i.output.request_id]?.[k] === i.output[k])).length;
  const rows = d.items.map((i) => {
    const gt = d.truth[i.output.request_id] || {};
    const ok = fields.slice(0, 3).every(([, k]) => gt[k] === i.output[k]);
    return h("tr", { onclick: () => showSample(i, gt) },
      h("td", {}, h("code", {}, i.output.request_id)),
      ...fields.map(([, k]) => h("td", {}, h("div", { class: "cell-pair" },
        h("span", { class: gt[k] === i.output[k] ? "" : "fail" }, i.output[k]), h("span", { class: "gt" }, `truth: ${gt[k] ?? "—"}`)))),
      h("td", {}, i.output.confidence_score),
      h("td", {}, h("span", { class: `engine-dot ${isAI(i.trace) ? "ai" : "rules"}` }), " ", isAI(i.trace) ? "Gemini" : "Rules"),
      h("td", { class: ok ? "pass" : "fail" }, ok ? "PASS" : "FAIL"));
  });
  $("#sampleTable").replaceChildren(
    h("div", { class: "kpis" },
      h("div", { class: "kpi", style: "--kc:var(--ok)" }, h("div", { class: "label" }, "Accuracy"), h("div", { class: "value" }, `${pass}/${d.items.length}`), h("div", { class: "sub" }, "severity + category + decision")),
      h("div", { class: "kpi", style: "--kc:var(--ai)" }, h("div", { class: "label" }, "Engine"), h("div", { class: "value" }, d.usage.models_used?.[0] || "rules"), h("div", { class: "sub" }, `${d.usage.successful_calls ?? 0} Gemini calls`))),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ...["ID", "Severity", "Category", "Decision", "Window", "Conf.", "Engine", "Result"].map((x) => h("th", {}, x)))),
      h("tbody", {}, ...rows))));
  if (d.items[0]) showSample(d.items[0], d.truth[d.items[0].output.request_id]);
}
function showSample(item, truth) { $("#sampleDetail").replaceChildren(...renderDetail(item, { truth })); }

// ── New triage ───────────────────────────────────────────────────────────
async function loadTemplates() {
  state.templates = await api("/api/templates");
  const sel = $("#templateSel");
  for (const [group, list] of Object.entries(state.templates)) {
    sel.append(h("optgroup", { label: group }, ...list.map((inc, idx) =>
      h("option", { value: `${group}::${idx}` }, `${inc.request_id} · ${inc.affected_entity_id}`))));
  }
}
$("#templateSel").addEventListener("change", (e) => {
  if (!e.target.value) return;
  const [g, idx] = e.target.value.split("::");
  const inc = state.templates[g][Number(idx)], f = $("#triageForm");
  for (const k of ["request_id", "timestamp", "source_system", "affected_entity_id", "entity_type", "incident_description"]) f.elements[k].value = inc[k] || "";
  const raw = parseJSON(inc.raw_signal_data, null);
  f.elements.raw_signal_data.value = raw ? JSON.stringify(raw, null, 2) : inc.raw_signal_data;
  $("#formError").textContent = "";
});
$("#triageForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target, err = $("#formError"), btn = $("#triageBtn");
  const body = Object.fromEntries(new FormData(f).entries());
  const raw = body.raw_signal_data.trim() || "{}";
  const parsed = parseJSON(raw, undefined);
  if (parsed === undefined || typeof parsed !== "object" || Array.isArray(parsed) || parsed === null) {
    err.textContent = "Raw signal data must be a valid JSON object, e.g. {\"source_ip\": \"1.2.3.4\"}"; return;
  }
  body.raw_signal_data = JSON.stringify(parsed);
  body.use_llm = $("#useLlm").checked;
  err.textContent = "";
  btn.disabled = true; btn.replaceChildren(h("span", { class: "spinner" }), body.use_llm ? "Gemini reasoning…" : "Triaging…");
  $("#triageResult").replaceChildren(h("div", { class: "skeleton" }), h("div", { class: "skeleton", style: "margin-top:14px" }));
  try {
    const res = await api("/api/triage", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    $("#triageResult").replaceChildren(...renderDetail(res, { elapsed: res.elapsed_s }));
    toast(isAI(res.trace) ? "Triaged with Gemini + guardrails" : "Triaged with deterministic engine");
  } catch (ex) {
    err.textContent = ex.message;
    $("#triageResult").replaceChildren(h("div", { class: "empty" }, `Triage failed: ${ex.message}`));
  } finally {
    btn.disabled = false; btn.textContent = "Run triage";
  }
});

// ── Usage ────────────────────────────────────────────────────────────────
async function renderUsage() {
  const d = state.set === "benchmark" ? state.data : await api("/api/results?set=benchmark");
  const u = d.usage || {}, s = state.status;
  const card = (lab, val, sub) => h("div", { class: "kpi" }, h("div", { class: "label" }, lab), h("div", { class: "value" }, val), h("div", { class: "sub" }, sub || ""));
  const engines = Object.entries(u.engine_per_incident || {});
  const runBtn = h("button", { class: "btn primary", onclick: rerun }, "Re-run benchmark");
  async function rerun() {
    runBtn.disabled = true; runBtn.replaceChildren(h("span", { class: "spinner" }), "Running 10 incidents…");
    try {
      const r = await api("/api/run-benchmark", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ use_llm: s.key_configured }) });
      toast(`Re-run finished in ${r.wall_time_s}s — showing it in the queue`);
      state.status = await api("/api/status"); renderStatus();
      $("#datasetSel").value = "ui"; state.set = "ui"; await loadQueue();
      document.querySelector('.tab[data-view="queue"]').click();
    } catch (ex) { toast(ex.message); }
    finally { runBtn.disabled = false; runBtn.textContent = "Re-run benchmark"; }
  }
  $("#usage").replaceChildren(
    h("div", { class: "section-head" }, h("h2", {}, "Engine & usage"),
      h("p", {}, "Measured by the agent for the submitted benchmark run (", h("code", {}, "evaluation/usage_benchmark.json"), ").")),
    h("div", { class: "card" },
      h("div", { class: "card-title" }, "Hybrid architecture"),
      h("div", { class: "flow" },
        h("div", {}, h("b", {}, "1 · Ingest"), "CSV + policy loaded once; JSON signals parsed safely"),
        h("div", {}, h("b", {}, "2 · Evidence"), "Deterministic corpus lookups; description treated as untrusted"),
        h("div", {}, h("b", {}, "3 · Policy rules"), "NOVAPAY-CAT/SEV rules; decisive matches lock the decision"),
        h("div", { class: "ai" }, h("b", {}, "4 · Gemini"), "Structured JSON reasoning, briefing, second opinion"),
        h("div", {}, h("b", {}, "5 · Guardrails"), "Validate, repair or fall back; engine recorded per row"))),
    h("div", { class: "usage-grid", style: "margin-top:14px" },
      card("Model used", (u.models_used || ["—"]).join(", "), u.models_quota_exhausted?.length ? `quota hit: ${u.models_quota_exhausted.join(", ")}` : "primary model"),
      card("API calls", `${u.successful_calls ?? 0} / ${u.http_calls ?? 0}`, "successful / total (incl. retries)"),
      card("Input tokens", (u.input_tokens ?? 0).toLocaleString(), `${Math.round((u.input_tokens || 0) / (u.incidents || 1)).toLocaleString()} per incident`),
      card("Output tokens", (u.output_tokens ?? 0).toLocaleString(), `${Math.round((u.output_tokens || 0) / (u.incidents || 1)).toLocaleString()} per incident`),
      card("Avg latency", `${u.avg_latency_s ?? 0}s`, `max ${u.max_latency_s ?? 0}s per call`),
      card("Wall time", `${u.wall_time_s ?? 0}s`, `${u.incidents ?? 0} incidents, sequential`)),
    h("div", { class: "card", style: "margin-top:14px" },
      h("div", { class: "card-title" }, "Engine per incident"),
      h("div", { class: "engine-list" }, ...engines.map(([id, eng]) => h("div", { class: "engine-item" },
        h("span", { class: `engine-dot ${eng === "gemini+guardrails" ? "ai" : "rules"}` }), h("code", {}, id),
        h("span", {}, eng === "gemini+guardrails" ? "Gemini" : "Fallback"))))),
    h("div", { class: "card", style: "margin-top:14px" },
      h("div", { class: "card-title" }, "Run again"),
      h("p", { style: "margin:0 0 12px;color:var(--text-2)" },
        "Re-runs all 10 incidents ", s.key_configured ? "with Gemini (uses ~10 free-tier requests)" : "with the deterministic engine (no API key set)",
        ". Results are saved to ", h("code", {}, "evaluation/ui_benchmark.csv"), "; the submitted ", h("code", {}, "output.csv"), " is never modified."),
      runBtn),
    h("div", { class: "card", style: "margin-top:14px" },
      h("div", { class: "card-title" }, "Fallback chain"),
      h("div", { class: "chips" }, ...s.models.map((m, i) => h("span", { class: "chip" }, `${i + 1}. ${m}`)),
        h("span", { class: "chip" }, `${s.models.length + 1}. deterministic policy engine`))),
  );
}

// ── Boot ─────────────────────────────────────────────────────────────────
(async function boot() {
  try {
    state.status = await api("/api/status");
    renderStatus();
    await Promise.all([loadQueue(), loadTemplates()]);
  } catch (ex) {
    $("#detail").replaceChildren(h("div", { class: "empty" }, `Could not reach the agent server: ${ex.message}`));
  }
})();
