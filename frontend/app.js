"use strict";
/* ==========================================================================
   Mougle Protect - interface web (aucune dependance, aucun framework)
   Organisation du fichier :
     1. utilitaires de rendu          6. entrainement, jeux de donnees, EMBER
     2. console (panneau noir)        7. services en ligne (API externes)
     3. acces par code (mode mobile)  8. actions (boutons) et liaisons
     4. composants communs            9. demarrage
     5. pages (vues)
   SECURITE : aucune donnee n'est inseree avec innerHTML ; tout passe par h() et
   textContent, donc un nom de fichier ou un lien hostile ne peut pas injecter de code.
   ========================================================================== */

/* ---------- utilitaires (aucune insertion de HTML : tout passe par textContent) */
const $ = (sel, root = document) => root.querySelector(sel);

function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "onclick") node.addEventListener("click", value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return node;
}

const LEVELS = {
  AUCUN_INDICATEUR_DETECTE: ["Aucun indicateur", "none"],
  SUSPECT: ["Suspect", "suspect"],
  RISQUE_ELEVE: ["Risque élevé", "high"],
};

// Gravite d'un indicateur : mot francais affiche a la place du code technique.
const SEVERITY = { critical: "Critique", high: "Élevé", medium: "Moyen", low: "Faible", info: "Info" };

function badge(level) {
  const [label, cls] = LEVELS[level] || [level, "none"];
  return h("span", { class: `badge lvl-${cls}` }, label);
}

function scorebar(risk) {
  const cls = (LEVELS[risk.level] || [0, "none"])[1];
  const bar = h("div", { class: `scorebar ${cls}`, title: `Score ${risk.score}/100` },
    h("i"));
  bar.firstChild.style.width = `${Math.min(100, risk.score)}%`;
  return bar;
}

/* ---------- console (colonne de droite) */
function isMobile() {
  return !!(window.matchMedia && window.matchMedia("(max-width:820px)").matches);
}
function localStorage_get(key) { try { return localStorage.getItem(key); } catch (_) { return null; } }
function setConsole(open) {
  if (isMobile()) {
    $("#console").classList.toggle("open", open);
  } else {
    $(".app").classList.toggle("console-hidden", !open);
    try { localStorage.setItem("mp_console_hidden", open ? "0" : "1"); } catch (_) { /* ignore */ }
  }
}

function clog(message, kind = "info") {
  const box = $("#console-log");
  if (!box) return;
  const tags = { info: "INFO", ok: "OK", warn: "ALRT", err: "ERR" };
  const time = h("time", {}, new Date().toLocaleTimeString("fr-FR"));
  const line = h("div", { class: `cl ${kind}` }, time, h("span", { class: "tag" }, tags[kind] || "INFO"), h("span", {}, message));
  box.append(line);
  while (box.children.length > 500) box.firstChild.remove();
  box.scrollTop = box.scrollHeight;
}

/* ---------- accès (mode réseau local / Android : code d'accès) */
const TOKEN_KEY = "mp_token";
(function () {
  const t = new URLSearchParams(location.search).get("token");
  if (t) {
    try { localStorage.setItem(TOKEN_KEY, t); } catch (_) { /* stockage indisponible */ }
    history.replaceState(null, "", location.pathname);
  }
})();
function authHeaders() {
  let t = null;
  try { t = localStorage.getItem(TOKEN_KEY); } catch (_) { /* ignore */ }
  return t ? { "X-Access-Token": t } : {};
}

function toast(message, isError = false) {
  if (isError) clog(message, "err");
  const el = $("#toast");
  el.textContent = message;
  el.className = isError ? "toast err" : "toast";
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { el.hidden = true; }, 4500);
}

async function api(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const loud = method !== "GET";          // les rafraîchissements automatiques restent silencieux
  const t0 = performance.now();
  if (loud) clog(`${method} ${path}`, "info");
  const response = await fetch(path, { ...options, headers: { ...authHeaders(), ...(options.headers || {}) } });
  if (loud) clog(`← ${response.status} (${Math.round(performance.now() - t0)} ms)`, response.ok ? "ok" : "err");
  if (response.status === 401) {
    const code = typeof prompt === "function" ? prompt("Code d'accès Mougle Protect :") : null;
    if (code) { try { localStorage.setItem(TOKEN_KEY, code.trim()); } catch (_) { /* ignore */ } }
    throw new Error("Code d'accès manquant ou invalide.");
  }
  let body = null;
  try { body = await response.json(); } catch (_) { /* corps vide */ }
  if (!response.ok) {
    const detail = body && body.detail;
    throw new Error(typeof detail === "string" ? detail : `Erreur ${response.status}`);
  }
  return body;
}

const post = (path, data) => api(path, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(data || {}),
});

function fmtBytes(n) {
  if (n === null || n === undefined) return "—";
  const units = ["o", "Ko", "Mo", "Go"];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${units[i]}`;
}

function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString("fr-FR");
}

const SOURCES = {
  file: "Fichier", application: "Application", link: "Lien",
  process: "Processus", network: "Réseau", file_activity: "Activité fichiers",
};

/* ---------- rendus communs */
function indicatorList(indicators) {
  if (!indicators || !indicators.length) return h("p", { class: "muted" }, "Aucune observation.");
  return h("ul", { class: "clean" }, indicators.map((i) =>
    h("li", {}, h("span", { class: `sev ${i.severity}` }, SEVERITY[i.severity] || i.severity), i.reason || i.code)));
}

function actionsBox(decision) {
  if (!decision || !decision.recommended_actions) return null;
  return h("div", { class: "actions" },
    h("strong", {}, "Actions recommandées"),
    h("ul", { class: "clean" }, decision.recommended_actions.map((a) => h("li", {}, a))));
}

function feedbackRow(scanId) {
  const send = (label) => async (e) => {
    try {
      await post("/api/feedback", { scan_id: scanId, label });
      toast(label === "malware" ? "Noté comme malveillant : ajouté à l'entraînement." : "Noté comme sûr : ajouté à l'entraînement.");
      clog(`Retour utilisateur enregistré (${label === "malware" ? "malveillant" : "sûr"}).`, "ok");
      e.target.parentElement.querySelectorAll("button").forEach((b) => { b.disabled = true; });
    } catch (err) { toast(err.message, true); }
  };
  return h("div", { class: "fb" },
    h("span", { class: "muted" }, "Ce résultat est-il correct ?"),
    h("button", { class: "btn small ghost", onclick: send("malware") }, "C'est malveillant"),
    h("button", { class: "btn small ghost", onclick: send("benign") }, "C'est sûr"));
}

// Verdicts des services externes (MalwareBazaar, URLhaus, VirusTotal...) en phrases claires.
const VERDICT_LABEL = { malicious: "Dangereux", suspicious: "À vérifier", clean: "Rien trouvé", unknown: "Inconnu", error: "Indisponible" };
function verdictList(online) {
  if (!online || !online.enabled || !online.verdicts || !online.verdicts.length) return null;
  const rows = online.verdicts.map((v) => h("div", { class: "verdict" },
    h("b", {}, v.title),
    h("div", {},
      h("span", { class: `badge lvl-${v.status === "malicious" ? "high" : v.status === "suspicious" ? "suspect" : "none"}` },
        VERDICT_LABEL[v.status] || v.status), " ", v.headline,
      v.reference && /^https:\/\//.test(v.reference)
        ? h("span", {}, " ", h("a", { href: v.reference, target: "_blank", rel: "noopener noreferrer" }, "détails")) : null),
    v.advice && v.status !== "unknown" ? h("div", { class: "advice" }, v.advice) : null));
  return h("div", { class: "verdicts" }, h("h3", {}, "Ce que disent les services en ligne"),
    online.summary ? h("p", {}, online.summary.text) : null, rows);
}

function resultCard(r) {
  const title = r.url || r.application || r.file_name || "Élément";
  const rows = [];
  const add = (k, v) => { if (v !== undefined && v !== null && v !== "") rows.push(h("dt", {}, k), h("dd", {}, v)); };
  add("Chemin", r.file_path);
  add("Domaine", r.registrable_domain);
  add("SHA-256", r.sha256);
  add("Taille", r.size_bytes !== undefined ? fmtBytes(r.size_bytes) : null);
  if (r.digital_signature) {
    add("Signature", r.digital_signature.status);
    add("Éditeur", r.digital_signature.signer);
  }
  if (r.deep) {
    add("Type détecté", r.deep.file_type);
    add("Familles de malwares", (r.deep.families || []).join(", "));
    add("Capacités détectées", Object.keys(r.deep.capabilities || {}).join(", "));
    add("Analyse du contenu", r.deep.partial_scan ? "partielle (début et fin du fichier)" : "complète");
    add("Modèle entraîné", r.deep.ml && r.deep.ml.available
      ? `${Math.round(r.deep.ml.probability * 100)} % de probabilité de malveillance`
      : "aucun modèle entraîné (voir Entraînement)");
  }
  if (r.deep && r.deep.ember) {
    const e = r.deep.ember;
    add("Modèle EMBER", e.available
      ? (e.probability !== undefined ? `${Math.round(e.probability * 100)} % de probabilité de malveillance` : "non applicable à ce fichier")
      : "inactif (voir Données et entraînement)");
  }
  if (r.deep && r.deep.known_benign) add("Liste de fichiers sains", `présent dans « ${r.deep.known_benign} »`);
  if (r.local_intel) add("Liste de menaces", `« ${r.local_intel.source} » (${r.local_intel.match === "url" ? "lien exact" : "domaine"})`);
  if (r.pe_header_valid !== undefined) add("En-tête programme Windows", r.pe_header_valid ? "valide" : "absent");
  if (r.entropy !== undefined && r.entropy !== null) add("Entropie", `${r.entropy} / 8`);

  return h("div", { class: "panel" },
    h("div", { class: "item-head" },
      h("span", { class: "item-title" }, title),
      scorebar(r.risk), h("span", { class: "muted" }, `${r.risk.score}/100`), badge(r.risk.level)),
    h("dl", { class: "kv" }, rows),
    indicatorList(r.risk_indicators),
    verdictList(r.online),
    actionsBox(r.decision),
    r.scan_id && r.deep ? feedbackRow(r.scan_id) : null,
    h("p", { class: "notice" }, r.notice || r.risk.limitations));
}

function logScanSummary(p) {
  const items = p.result ? [p.result] : (p.applications || p.results || (p.risk ? [p] : []));
  const counts = { RISQUE_ELEVE: 0, SUSPECT: 0, AUCUN_INDICATEUR_DETECTE: 0 };
  items.slice(0, 15).forEach((r) => {
    if (!r.risk) return;
    const lvl = r.risk.level;
    const kind = lvl === "RISQUE_ELEVE" ? "err" : lvl === "SUSPECT" ? "warn" : "ok";
    clog(`${r.url || r.application || r.file_name || "élément"} · ${(LEVELS[lvl] || [lvl])[0]} · ${r.risk.score}/100`, kind);
  });
  items.forEach((r) => { if (r.risk && r.risk.level in counts) counts[r.risk.level]++; });
  if (items.length > 15) clog(`… ${items.length - 15} autre(s) résultat(s) dans la page`, "info");
  clog(`Bilan : ${items.length} élément(s) — ${counts.RISQUE_ELEVE} risque élevé, ${counts.SUSPECT} suspect(s), ${counts.AUCUN_INDICATEUR_DETECTE} sans indicateur.`,
    counts.RISQUE_ELEVE ? "err" : counts.SUSPECT ? "warn" : "ok");
}

function renderScanOutput(target, payload) {
  logScanSummary(payload);
  target.replaceChildren();
  if (payload.results && payload.type !== "directory" && !payload.type) {
    payload.results.forEach((r) => target.append(resultCard(r)));
  } else if (payload.type === "file") {
    target.append(resultCard(payload.result));
  } else if (payload.type === "directory") {
    target.append(h("div", { class: "panel" },
      h("div", { class: "item-head" },
        h("span", { class: "item-title" }, payload.directory), badge(payload.overall_level)),
      h("p", { class: "muted" },
        `${payload.files_examined} fichier(s) analysé(s), ${payload.files_to_review} à vérifier` +
        (payload.truncated ? " (liste tronquée)" : "") + `, ${payload.errors.length} erreur(s).`),
      h("p", { class: "notice" }, payload.notice)));
    sortByRisk(payload.results).forEach((r) => target.append(resultCard(r)));
  } else if (payload.applications) {
    target.append(h("div", { class: "panel" },
      h("div", { class: "item-head" },
        h("span", { class: "item-title" }, "Applications en cours d'exécution"),
        badge(payload.overall_level)),
      h("p", { class: "muted" },
        `${payload.applications_examined} application(s) analysée(s), ${payload.to_review} avec observations.`),
      h("p", { class: "notice" }, payload.notice)));
    sortByRisk(payload.applications).forEach((r) => target.append(resultCard(r)));
  } else if (payload.risk) {
    target.append(resultCard(payload));
  }
}

const sortByRisk = (items) => [...items].sort((a, b) => b.risk.score - a.risk.score);

/* ---------- navigation */
let currentView = "dashboard";

const PAGES = {
  dashboard: ["Vue d'ensemble", "L'état de votre ordinateur en un coup d'œil"],
  alerts: ["Alertes", "Ce qui demande votre attention, avec les gestes recommandés"],
  processes: ["Programmes en cours", "Ce qui tourne sur cet ordinateur en ce moment"],
  network: ["Réseau", "Les connexions actives vers l'extérieur"],
  scan: ["Analyser", "Liens, fichiers et applications — sans jamais rien exécuter"],
  training: ["Données et entraînement", "Nourrir et entraîner les modèles de détection"],
  connections: ["Services en ligne", "Interroger des bases de menaces publiques (facultatif)"],
  history: ["Historique", "Les analyses déjà faites"],
};

function showView(name) {
  currentView = name;
  $("#page-title").textContent = PAGES[name][0];
  $("#page-sub").textContent = PAGES[name][1];
  document.querySelectorAll(".view").forEach((v) => { v.hidden = v.id !== `view-${name}`; });
  document.querySelectorAll("#nav button").forEach((b) =>
    b.classList.toggle("active", b.dataset.view === name));
  refresh();
}

/* ---------- vues */
async function loadStatus() {
  const s = await api("/api/status");
  const pill = $("#monitor-pill"), btn = $("#btn-monitor");
  pill.textContent = s.monitor.running ? "Surveillance active" : "Surveillance arrêtée";
  pill.className = `pill ${s.monitor.running ? "on" : "off"}`;
  btn.textContent = s.monitor.running ? "Arrêter" : "Démarrer";
  btn.dataset.running = s.monitor.running ? "1" : "0";

  $("#stat-open").textContent = s.counts.open_alerts;
  $("#stat-high").textContent = s.counts.open_high;
  $("#stat-suspect").textContent = s.counts.open_suspect;
  $("#stat-scans").textContent = s.counts.scans;
  $("#stat-cycles").textContent = s.monitor.cycles;

  // Bandeau d'accueil : une phrase humaine plutot qu'un tableau de chiffres.
  const hero = $("#status-hero");
  if (hero) {
    const high = s.counts.open_high, sus = s.counts.open_suspect;
    const plural = (n, one, many) => `${n} ${n > 1 ? many : one}`;
    let cls = "status-hero", title, text;
    if (high > 0) {
      cls += " high";
      title = `Attention : ${plural(high, "élément dangereux", "éléments dangereux")}`;
      text = "Ne les ouvrez pas. Ouvrez la page Alertes pour savoir quoi faire.";
    } else if (sus > 0) {
      cls += " warn";
      title = `${plural(sus, "élément à vérifier", "éléments à vérifier")}`;
      text = "Rien de grave d'après nos analyses, mais un contrôle de votre part est conseillé.";
    } else {
      title = "Tout est calme";
      text = s.monitor.running
        ? "Aucun signe de problème pour l'instant. La surveillance veille."
        : "Aucun signe de problème, mais la surveillance est arrêtée : démarrez-la pour être alerté.";
    }
    hero.className = cls;
    $("#status-title").textContent = title;
    $("#status-text").textContent = text;
  }

  const navCount = $("#nav-alert-count");
  navCount.textContent = s.counts.open_alerts;
  navCount.hidden = s.counts.open_alerts === 0;

  const kv = $("#dash-monitor");
  kv.replaceChildren(
    h("dt", {}, "Intervalle"), h("dd", {}, `${s.monitor.interval_seconds} s`),
    h("dt", {}, "Dernier cycle"), h("dd", {}, fmtDate(s.monitor.last_cycle_at)),
    h("dt", {}, "Dossiers surveillés"),
    h("dd", {}, s.monitor.watched_directories.length ? s.monitor.watched_directories.join(", ") : "aucun"),
    h("dt", {}, "Signatures"),
    h("dd", {}, s.signature_check ? "vérifiées (Authenticode)" : "non disponibles sur ce système"),
    s.monitor.last_error ? [h("dt", {}, "Erreur"), h("dd", {}, s.monitor.last_error)] : null);
}

function alertItem(a, withAck = true) {
  const decision = a.details && a.details.decision;
  const risk = a.details && a.details.risk;
  const item = h("div", { class: `item${a.acknowledged ? " acked" : ""}` },
    h("div", { class: "item-head" },
      badge(a.level),
      h("span", { class: "muted" }, SOURCES[a.source] || a.source),
      h("span", { class: "item-title" }, a.title),
      h("span", { class: "muted" }, fmtDate(a.created_at)),
      withAck && !a.acknowledged ? h("button", { class: "btn small ghost", onclick: async () => {
        try { await api(`/api/alerts/${a.id}/ack`, { method: "POST" }); refresh(); }
        catch (e) { toast(e.message, true); }
      } }, "Acquitter") : null),
    risk ? h("p", { class: "muted" }, `Score ${risk.score}/100`) : null,
    a.details && a.details.indicators ? indicatorList(a.details.indicators) : null,
    risk && !(a.details && a.details.indicators) ? h("ul", { class: "clean" },
      risk.main_reasons.map((r) => h("li", {}, r))) : null,
    h("details", {}, h("summary", {}, "Actions recommandées"), actionsBox(decision)),
    a.details && a.details.scan_id && (a.source === "file" || a.source === "application") ? feedbackRow(a.details.scan_id) : null);
  return item;
}

async function loadDashboard() {
  const [, data] = await Promise.all([loadStatus(),
    api("/api/alerts?acknowledged=false&limit=5")]);
  const box = $("#dash-alerts");
  box.replaceChildren(...(data.alerts.length
    ? data.alerts.map((a) => alertItem(a, false))
    : [h("div", { class: "empty" }, "Aucune alerte ouverte.")]));

  const act = await api("/api/file-activity");
  $("#dash-activity").textContent = act.baseline
    ? "Référence en cours de constitution."
    : `${act.created} créé(s), ${act.modified} modifié(s), ${act.deleted} supprimé(s) au dernier cycle ` +
      `(${act.files_watched} fichiers surveillés).`;
}

async function loadAlerts() {
  const level = $("#alert-level").value;
  const showAck = $("#alert-show-ack").checked;
  const params = new URLSearchParams({ limit: "200" });
  if (level) params.set("level", level);
  if (!showAck) params.set("acknowledged", "false");
  const [, data] = await Promise.all([loadStatus(), api(`/api/alerts?${params}`)]);
  $("#alerts-list").replaceChildren(...(data.alerts.length
    ? data.alerts.map((a) => alertItem(a))
    : [h("div", { class: "empty" }, "Aucune alerte.")]));
}

async function loadProcesses() {
  const only = $("#proc-flagged").checked;
  const [, data] = await Promise.all([loadStatus(), api(`/api/processes?only_flagged=${only}`)]);
  $("#proc-count").textContent = `${data.count} processus`;
  const body = $("#proc-table tbody");
  body.replaceChildren(...data.processes.slice(0, 300).map((p) => h("tr", {},
    h("td", {}, p.pid), h("td", { title: p.executable || "" }, p.name),
    h("td", {}, p.parent_name || "—"),
    h("td", {}, p.cpu_percent ?? "—"), h("td", {}, fmtBytes(p.memory_rss_bytes)),
    h("td", {}, p.anomaly ? `oui (${p.anomaly_score})` : (p.anomaly_score === null ? "—" : "non")),
    h("td", {}, badge(p.risk.level)),
    h("td", {}, p.indicators.map((i) => h("div", {}, h("span", { class: `sev ${i.severity}` }, i.severity), i.reason))))));
}

async function loadNetwork() {
  const [, data] = await Promise.all([loadStatus(), api("/api/network")]);
  const findings = (data.findings || []).filter((f) => f.risk && f.risk.level !== "AUCUN_INDICATEUR_DETECTE");
  $("#net-findings").replaceChildren(...(findings.length
    ? findings.map((f) => h("div", { class: "item" },
      h("div", { class: "item-head" }, badge(f.risk.level),
        h("span", { class: "item-title" }, `${f.process || "?"} (PID ${f.pid})`),
        h("span", { class: "muted" }, `${f.external_connections} connexion(s)`)),
      indicatorList(f.indicators)))
    : [h("div", { class: "empty" }, "Aucun constat réseau.")]));
  const external = (data.connections || []).filter((c) => c.external);
  $("#net-table tbody").replaceChildren(...external.slice(0, 300).map((c) => h("tr", {},
    h("td", {}, c.pid ?? "—"), h("td", {}, c.process || "—"),
    h("td", {}, c.remote_ip), h("td", {}, c.remote_port), h("td", {}, c.status))));
  $("#net-note").textContent = data.available === false
    ? `Connexions indisponibles : ${data.error}` : `${external.length} connexion(s) externe(s).`;
}

async function loadHistory() {
  const [, data] = await Promise.all([loadStatus(), api("/api/scans?limit=100")]);
  $("#history-list").replaceChildren(...(data.scans.length
    ? data.scans.map((s) => h("div", { class: "item" },
      h("div", { class: "item-head" }, badge(s.level),
        h("span", { class: "muted" }, SOURCES[s.kind] || s.kind),
        h("span", { class: "item-title" }, s.target),
        h("span", { class: "muted" }, fmtDate(s.created_at)),
        h("button", { class: "btn small ghost", onclick: async () => {
          try {
            const full = await api(`/api/scans/${s.id}`);
            $("#history-detail").replaceChildren(resultCard(full.report));
          } catch (e) { toast(e.message, true); }
        } }, "Détails"))))
    : [h("div", { class: "empty" }, "Aucune analyse enregistrée.")]));
}

async function refresh() {
  try {
    if (currentView === "dashboard") await loadDashboard();
    else if (currentView === "alerts") await loadAlerts();
    else if (currentView === "processes") await loadProcesses();
    else if (currentView === "network") await loadNetwork();
    else if (currentView === "training") await loadTraining();
    else if (currentView === "connections") await loadConnections();
    else if (currentView === "history") await loadHistory();
    else await loadStatus();
  } catch (e) { toast(e.message, true); }
}

/* ---------- entraînement */
async function loadTraining() {
  const s = await api("/api/training/status");
  await Promise.all([loadEmber(s.jobs), loadDatasets(s.jobs)]);
  const m = s.active_model;
  $("#tr-model").replaceChildren(
    h("dt", {}, "Modèle actif"), h("dd", {}, m ? `#${m.id} — entraîné le ${fmtDate(m.created_at)}` : "aucun (entraînement requis)"),
    m ? [h("dt", {}, "F1 / rappel / précision"), h("dd", {}, `${m.metrics.f1} / ${m.metrics.recall} / ${m.metrics.precision}`),
         h("dt", {}, "Échantillons"), h("dd", {}, `${m.n_samples} (test : ${m.metrics.n_test})`)] : null,
    h("dt", {}, "Prêt à entraîner"), h("dd", {}, s.ready ? "oui" : `non — il faut au moins ${s.min_per_class} échantillons sains et ${s.min_per_class} malveillants`),
    h("dt", {}, "Nouveaux depuis le dernier"), h("dd", {}, `${s.new_since_last_training} (réentraînement auto à ${s.auto_train_min_new})`));
  $("#tr-auto").checked = s.auto_train;
  $("#tr-data").replaceChildren(
    h("dt", {}, "Hachages malveillants connus"), h("dd", {}, String(s.known_hashes)),
    h("dt", {}, "Échantillons malveillants"), h("dd", {}, String(s.samples.malware)),
    h("dt", {}, "Échantillons sains"), h("dd", {}, String(s.samples.benign)),
    h("dt", {}, "Sources"), h("dd", {}, Object.entries(s.samples.by_source).map(([k, v]) => `${k} : ${v}`).join(", ") || "—"),
    h("dt", {}, "Caractéristiques / fichier"), h("dd", {}, String(s.feature_count)));
  const running = s.jobs.filter((j) => j.status === "running").pop() || s.jobs[s.jobs.length - 1];
  const box = $("#tr-job");
  box.replaceChildren();
  if (running) {
    const pct = running.total ? Math.round((running.progress / running.total) * 100) : (running.status === "done" ? 100 : 5);
    const bar = h("div", { class: "bar" }, h("i")); bar.firstChild.style.width = `${pct}%`;
    box.append(h("div", {}, `Tâche « ${running.kind} » : ${running.status === "running" ? "en cours" : running.status === "done" ? "terminée" : "erreur"}`
      + (running.total ? ` — ${running.progress}/${running.total}` : "") + (running.message ? ` — ${running.message}` : "")), bar);
    if (running.status === "done" && running.result && running.result.metrics && !running.logged) {
      running.logged = true;
    }
  }
  const body = $("#tr-models tbody");
  body.replaceChildren(...(s.models.length ? s.models.map((mod) => h("tr", {},
    h("td", {}, mod.id), h("td", {}, fmtDate(mod.created_at)), h("td", {}, mod.n_samples),
    h("td", {}, mod.metrics.f1), h("td", {}, mod.metrics.recall), h("td", {}, mod.metrics.precision),
    h("td", {}, mod.active ? h("span", { class: "badge lvl-none" }, "actif")
      : h("button", { class: "btn small ghost", onclick: (e) => withButton(e.currentTarget, async () => {
          await post(`/api/training/activate/${mod.id}`); refresh(); }) }, "Activer"))))
    : [h("tr", {}, h("td", { colspan: 7, class: "empty" }, "Aucun modèle entraîné pour l'instant.")) ]));
}

async function waitJob(job) {
  for (;;) {
    const j = await api(`/api/training/jobs/${job.id}`);
    loadTraining().catch(() => {});
    if (j.status !== "running") {
      if (j.status === "error") throw new Error(j.message);
      return j.result;
    }
    await new Promise((r) => setTimeout(r, 800));
  }
}

/* ---------- 6b. modele EMBER, jeux de donnees, menaces connues */
const pct = (x) => (x === undefined || x === null ? "—" : `${(x * 100).toFixed(1)} %`);

// Barre de progression d'une tache de fond (entrainement, ingestion, import...).
function renderJob(box, job) {
  box.replaceChildren();
  if (!job) return;
  const state = job.status === "running" ? "en cours" : job.status === "done" ? "terminée" : "en erreur";
  const percent = job.total ? Math.round((job.progress / job.total) * 100) : (job.status === "done" ? 100 : 5);
  const bar = h("div", { class: "bar" }, h("i")); bar.firstChild.style.width = `${percent}%`;
  box.append(h("div", {}, `Tâche « ${job.kind} » ${state}` + (job.total ? ` — ${job.progress}/${job.total}` : "")
    + (job.message ? ` — ${job.message}` : "")), bar);
}

function latestJob(jobs, kinds) {
  const mine = (jobs || []).filter((j) => kinds.includes(j.kind));
  return mine.find((j) => j.status === "running") || mine[mine.length - 1];
}

async function loadEmber(jobs) {
  const s = await api("/api/ember/status");
  const a = s.active || {};
  $("#em-status").replaceChildren(
    h("dt", {}, "État"), h("dd", {}, s.available ? "Actif" : (s.error || "Inactif")),
    a.model ? [h("dt", {}, "Modèle"), h("dd", {}, a.model),
               h("dt", {}, "Entraîné le"), h("dd", {}, fmtDate(a.trained_at)),
               h("dt", {}, "Fichiers d'entraînement"), h("dd", {}, (a.n_samples || 0).toLocaleString("fr-FR")),
               h("dt", {}, "Précision (AUC)"), h("dd", {}, a.auc ? a.auc.toFixed(4) : "—")] : null,
    h("dt", {}, "Vos fichiers ajoutés"),
    h("dd", {}, `${s.your_vectors.malware} malveillants, ${s.your_vectors.benign} sains`),
    h("dt", {}, "Données BODMAS"), h("dd", {}, s.bodmas_present ? "présentes" : "absentes (onglet Jeux de données)"));
  $("#em-auto").checked = s.auto_train;
  renderJob($("#em-job"), latestJob(jobs, ["ember"]));
  const body = $("#em-models tbody");
  body.replaceChildren(...(s.models.length ? s.models.map((m) => h("tr", {},
    h("td", {}, fmtDate(m.created_at)), h("td", {}, (m.n_total || 0).toLocaleString("fr-FR")),
    h("td", {}, m.metrics && m.metrics.roc_auc ? m.metrics.roc_auc.toFixed(4) : "—"),
    h("td", {}, m.metrics ? `${pct(m.metrics.tpr_high)} (fausses alertes : ${pct(m.metrics.fpr_high)})` : "—"),
    h("td", {}, m.active ? h("span", { class: "badge lvl-none" }, "actif")
      : h("button", { class: "btn small ghost", onclick: (e) => withButton(e.currentTarget, async () => {
          await post("/api/ember/activate", { file: m.file }); refresh(); }) }, "Activer"))))
    : [h("tr", {}, h("td", { colspan: 5, class: "empty" }, "Aucun modèle pour l'instant : lancez un entraînement.")) ]));
}

async function loadDatasets(jobs) {
  const d = await api("/api/datasets");
  $("#ds-list").replaceChildren(...d.datasets.map((ds) => h("div", { class: "dataset" },
    h("div", {},
      h("h3", {}, ds.title), h("p", { class: "muted" }, ds.description),
      h("p", { class: "muted" }, ds.present
        ? `${ds.rows.toLocaleString("fr-FR")} élément(s) · ${fmtBytes(ds.size_bytes)} · ${ds.path}`
        : `Dossier : ${ds.path}` + (ds.missing.length ? ` — manque : ${ds.missing.join(", ")}` : ""))),
    h("div", { class: "state" },
      h("span", { class: `badge lvl-${ds.present ? "none" : "suspect"}` }, ds.present ? "Présent" : "Absent"),
      ds.actions.map((act) => h("div", { class: "row", style: "margin:8px 0 0" },
        h("button", { class: "btn small ghost", onclick: (e) => withButton(e.currentTarget, async () => {
          const r = await waitJob(await post(`/api/datasets/${ds.name}/${act.id}`, {}));
          clog(`${ds.title} — ${act.label} : ${JSON.stringify(r)}`, "ok");
          refresh();
        }) }, act.label)))))));
  renderJob($("#ds-job"), latestJob(jobs, ["ingest", "intel"]));
  const c = d.intel;
  $("#intel-counts").replaceChildren(
    h("dt", {}, "Empreintes malveillantes"), h("dd", {}, c.malware_hashes.toLocaleString("fr-FR")),
    h("dt", {}, "Empreintes de fichiers sains"), h("dd", {}, c.benign_hashes.toLocaleString("fr-FR")),
    h("dt", {}, "Liens malveillants"), h("dd", {}, c.malicious_urls.toLocaleString("fr-FR")),
    h("dt", {}, "Sites signalés"), h("dd", {}, c.malicious_hosts.toLocaleString("fr-FR")),
    h("dt", {}, "Réponses en cache (services en ligne)"), h("dd", {}, c.cached_answers.toLocaleString("fr-FR")));
}

/* ---------- 7. services en ligne (API externes) */
async function loadConnections() {
  const s = await api("/api/online/settings");
  $("#on-master").checked = s.master;
  const seen = new Set();
  $("#on-providers").replaceChildren(...s.providers.map((p) => {
    const first = !seen.has(p.group); seen.add(p.group);
    return h("div", { class: "provider", "data-id": p.id, "data-group": p.group },
      h("div", {},
        h("h3", { style: "margin:0;color:var(--encre);font-family:var(--serif);font-size:16px" }, p.title),
        h("p", { class: "muted", style: "margin:2px 0" }, `Envoie : ${p.what_is_sent}.`),
        p.needs_key || p.group !== "phishtank"
          ? (first ? h("input", { type: "password", "data-key": p.group, autocomplete: "off",
              placeholder: p.key_hint ? `Clé enregistrée ${p.key_hint} (laisser vide pour la garder)` : "Coller la clé d'accès" })
            : h("p", { class: "muted" }, "Utilise la même clé abuse.ch que le service précédent."))
          : h("input", { type: "password", "data-key": p.group, autocomplete: "off", placeholder: "Clé facultative" }),
        h("p", { class: "muted" }, "Clé gratuite : ", h("a", { href: p.signup, target: "_blank", rel: "noopener noreferrer" }, p.signup))),
      h("div", {},
        h("label", { class: "check" }, h("input", { type: "checkbox", "data-enable": p.id, checked: p.enabled ? "checked" : null }), "Activé"),
        h("div", { class: "row", style: "margin:8px 0 0" },
          h("button", { class: "btn small ghost", onclick: (e) => withButton(e.currentTarget, async () => {
            const r = await post(`/api/online/test/${p.id}`, {});
            toast(r.message, !r.ok); clog(`Test ${p.title} : ${r.message}`, r.ok ? "ok" : "warn");
          }) }, "Tester"))));
  }));
}

async function saveConnections() {
  const keys = {}, enabled = {};
  document.querySelectorAll("#on-providers input[data-key]").forEach((el) => { if (el.value.trim()) keys[el.dataset.key] = el.value.trim(); });
  document.querySelectorAll("#on-providers input[data-enable]").forEach((el) => { enabled[el.dataset.enable] = el.checked; });
  await post("/api/online/settings", { master: $("#on-master").checked, enabled, keys });
  toast("Réglages enregistrés.");
  clog(`Services en ligne ${$("#on-master").checked ? "autorisés" : "désactivés"}.`, "info");
  loadConnections();
}

// Relie une barre d'onglets a ses panneaux (chaque panneau porte data-tab="nom").
function bindTabs(tabsSel, rootSel) {
  const tabs = document.querySelectorAll(`${tabsSel} button`);
  tabs.forEach((b) => b.addEventListener("click", () => {
    tabs.forEach((x) => x.classList.toggle("active", x === b));
    document.querySelectorAll(`${rootSel} .tab-panel`).forEach((p) => { p.hidden = p.dataset.tab !== b.dataset.tab; });
  }));
}

/* ---------- 8. actions */
async function withButton(button, task) {
  const label = button.textContent.trim();
  const t0 = performance.now();
  button.disabled = true;
  clog(`▶ ${label}`, "info");
  try {
    await task();
    clog(`✔ ${label} — terminé en ${Math.round(performance.now() - t0)} ms`, "ok");
  } catch (e) { toast(e.message, true); }
  finally { button.disabled = false; }
}

async function upload(kind) {
  const input = $("#file-input");
  if (!input.files.length) { toast("Choisissez d'abord un fichier.", true); return; }
  const form = new FormData();
  form.append("file", input.files[0]);
  const result = await api(`/api/scan/${kind}`, { method: "POST", body: form });
  renderScanOutput($("#scan-results"), result);
  loadStatus();
}

function bind() {
  document.querySelectorAll("#nav button").forEach((b) =>
    b.addEventListener("click", () => showView(b.dataset.view)));

  $("#btn-monitor").addEventListener("click", (e) => withButton(e.currentTarget, async () => {
    const running = e.currentTarget.dataset.running === "1";
    await post(running ? "/api/monitor/stop" : "/api/monitor/start");
    toast(running ? "Surveillance arrêtée." : "Surveillance démarrée.");
    refresh();
  }));

  $("#btn-run-once").addEventListener("click", (e) => withButton(e.currentTarget, async () => {
    const r = await post("/api/monitor/run-once");
    toast(`Cycle terminé : ${r.processes} processus, ${r.flagged_processes} signalé(s).`);
    refresh();
  }));

  $("#btn-report").addEventListener("click", (e) => withButton(e.currentTarget, async () => {
    const data = await api("/api/report");
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const link = h("a", { href: URL.createObjectURL(blob), download: "mougle_protect_rapport.json" });
    document.body.append(link); link.click(); link.remove();
  }));

  $("#btn-scan-links").addEventListener("click", (e) => withButton(e.currentTarget, async () => {
    const urls = $("#link-input").value.split("\n").map((u) => u.trim()).filter(Boolean);
    if (!urls.length) { toast("Saisissez au moins un lien.", true); return; }
    renderScanOutput($("#scan-results"), await post("/api/scan/links", { urls }));
    loadStatus();
  }));

  $("#btn-scan-file").addEventListener("click", (e) => withButton(e.currentTarget, () => upload("file")));
  $("#btn-scan-app").addEventListener("click", (e) => withButton(e.currentTarget, () => upload("application")));

  $("#btn-scan-path").addEventListener("click", (e) => withButton(e.currentTarget, async () => {
    const path = $("#path-input").value.trim();
    if (!path) { toast("Saisissez un chemin.", true); return; }
    renderScanOutput($("#scan-results"), await post("/api/scan/path", {
      path, kind: $("#path-kind").value, recursive: $("#path-recursive").checked }));
    loadStatus();
  }));

  $("#btn-scan-running").addEventListener("click", (e) => withButton(e.currentTarget, async () => {
    renderScanOutput($("#scan-results"), await post("/api/scan/running-applications"));
    loadStatus();
  }));

  bindTabs("#scan-tabs", "#view-scan");
  bindTabs("#train-tabs", "#view-training");
  $("#btn-em-train").addEventListener("click", (e) => withButton(e.currentTarget, async () => {
    const r = await waitJob(await post("/api/ember/train", { profile: $("#em-profile").value }));
    clog(`Modèle EMBER ${r.model} : AUC ${r.metrics.roc_auc.toFixed(4)}, détection ${pct(r.metrics.tpr_high)} à ${pct(r.metrics.fpr_high)} de fausses alertes.`, "ok");
    refresh();
  }));
  $("#em-auto").addEventListener("change", async (e) => {
    try { await post("/api/ember/auto", { enabled: e.target.checked }); clog(`Réentraînement automatique EMBER ${e.target.checked ? "activé" : "désactivé"}.`, "info"); }
    catch (err) { toast(err.message, true); }
  });
  $("#btn-intel-sync").addEventListener("click", (e) => withButton(e.currentTarget, async () => {
    const r = await waitJob(await post("/api/intel/sync?force=true", {}));
    clog(`Listes relues : ${r.length} fichier(s).`, "ok"); refresh();
  }));
  $("#btn-urls").addEventListener("click", (e) => withButton(e.currentTarget, async () => {
    const file = $("#url-file").files[0], kind = $("#url-kind").value;
    let r;
    if (file) {
      const f = new FormData(); f.append("file", file);
      r = await api(`/api/intel/urls/upload?kind=${kind}`, { method: "POST", body: f });
    } else {
      const text = $("#url-text").value;
      if (text.trim().length < 8) { toast("Collez au moins un lien ou choisissez un fichier.", true); return; }
      r = await post("/api/intel/urls", { text, kind });
    }
    clog(`Liens : ${r.found} trouvé(s), ${r.urls_added} liens et ${r.hosts_added} sites ajoutés.`, "ok"); refresh();
  }));
  $("#btn-on-save").addEventListener("click", (e) => withButton(e.currentTarget, saveConnections));
  $("#btn-on-check").addEventListener("click", (e) => withButton(e.currentTarget, async () => {
    const value = $("#on-check-value").value.trim();
    if (!value) { toast("Saisissez un lien ou une empreinte SHA-256.", true); return; }
    const kind = /^[a-f0-9]{64}$/i.test(value) ? "hash" : "url";
    const r = await post("/api/online/check", { kind, value });
    $("#on-check-results").replaceChildren(verdictList(r) || h("p", { class: "empty" }, "Aucun service activé n'a répondu."));
  }));
  $("#btn-train").addEventListener("click", (e) => withButton(e.currentTarget, async () => {
    const r = await waitJob(await post("/api/training/train", {}));
    clog(`Modèle #${r.model_id} : F1 ${r.metrics.f1}, rappel ${r.metrics.recall}, précision ${r.metrics.precision}`
      + (r.activated ? " — activé." : " — non activé (moins bon que l'actuel)."), r.activated ? "ok" : "warn");
    refresh();
  }));
  $("#tr-auto").addEventListener("change", async (e) => {
    try { await post("/api/training/auto", { enabled: e.target.checked }); clog(`Entraînement automatique ${e.target.checked ? "activé" : "désactivé"}.`, "info"); }
    catch (err) { toast(err.message, true); }
  });
  $("#btn-hashes").addEventListener("click", (e) => withButton(e.currentTarget, async () => {
    const file = $("#hash-file").files[0];
    let r;
    if (file) { const f = new FormData(); f.append("file", file); r = await api("/api/training/hashes/upload", { method: "POST", body: f }); }
    else {
      const text = $("#hash-text").value;
      if (text.trim().length < 64) { toast("Collez au moins un hachage SHA-256 ou choisissez un fichier.", true); return; }
      r = await post("/api/training/hashes", { text });
    }
    clog(`Hachages : ${r.found} trouvé(s), ${r.added} ajouté(s) — base : ${r.known_hashes}.`, "ok");
    refresh();
  }));
  $("#btn-ingest").addEventListener("click", (e) => withButton(e.currentTarget, async () => {
    const path = $("#ingest-path").value.trim();
    if (!path) { toast("Saisissez le chemin du dossier.", true); return; }
    const r = await waitJob(await post("/api/training/ingest-folder", {
      path, label: $("#ingest-label").value, recursive: $("#ingest-recursive").checked }));
    clog(`Dossier : ${r.added} ajouté(s), ${r.duplicates} déjà connu(s), ${r.errors} erreur(s).`, "ok");
    refresh();
  }));
  $("#btn-import-csv").addEventListener("click", (e) => withButton(e.currentTarget, async () => {
    const file = $("#csv-file").files[0];
    if (!file) { toast("Choisissez un fichier CSV.", true); return; }
    const f = new FormData(); f.append("file", file);
    const r = await api("/api/training/import-features", { method: "POST", body: f });
    clog(`CSV : ${r.added} échantillon(s) importé(s), ${r.rejected} rejeté(s).`, "ok");
    refresh();
  }));
  $("#btn-export").addEventListener("click", (e) => withButton(e.currentTarget, async () => {
    const res = await fetch("/api/training/export", { headers: authHeaders() });
    if (!res.ok) throw new Error(`Erreur ${res.status}`);
    const link = h("a", { href: URL.createObjectURL(await res.blob()), download: "mougle_protect_dataset.csv" });
    document.body.append(link); link.click(); link.remove();
  }));
  $("#console-clear").addEventListener("click", () => $("#console-log").replaceChildren());
  $("#console-toggle").addEventListener("click", () => setConsole(true));
  $("#console-close").addEventListener("click", () => setConsole(false));
  if (!isMobile() && localStorage_get("mp_console_hidden") === "1") setConsole(false);
  $("#results-clear").addEventListener("click", () =>
    $("#scan-results").replaceChildren(h("p", { class: "empty" }, "Aucune analyse lancée. Choisissez un onglet ci-dessus.")));

  ["#alert-level", "#alert-show-ack", "#proc-flagged"].forEach((s) =>
    $(s).addEventListener("change", refresh));
}

bind();
showView("dashboard");
clog("Mougle Protect prêt. Les actions lancées s'affichent ici.", "info");
if ("serviceWorker" in navigator && location.protocol !== "file:") {
  navigator.serviceWorker.register("/sw.js").catch(() => { /* HTTP non sécurisé : ignoré */ });
}
setInterval(refresh, 5000);
