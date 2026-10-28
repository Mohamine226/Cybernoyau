const { JSDOM, VirtualConsole } = require("jsdom");
const BASE = "http://127.0.0.1:8000";
const errors = [];
let passed = 0;
function check(name, cond, extra = "") {
  if (cond) { passed++; console.log("  ok  ", name); }
  else { console.log("  FAIL", name, extra); process.exitCode = 1; }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, ms = 8000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { try { if (fn()) return true; } catch (_) {} await sleep(100); }
  return false;
}
(async () => {
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => errors.push(String(e.message || e)));
  vc.on("error", (e) => errors.push(String(e)));
  const dom = await JSDOM.fromURL(BASE + "/", {
    runScripts: "dangerously", resources: "usable", pretendToBeVisual: true,
    virtualConsole: vc,
    beforeParse(window) {
      window.fetch = (u, o) => fetch(new URL(u, BASE).href, o);
    },
  });
  const { window } = dom, doc = window.document, $ = (s) => doc.querySelector(s);
  const click = (s) => $(s).dispatchEvent(new window.Event("click", { bubbles: true }));
  const nav = (v) => click(`#nav button[data-view="${v}"]`);

  console.log("Tableau de bord");
  check("surveillance active affichée", await waitFor(() => $("#monitor-pill").textContent === "Surveillance active"), $("#monitor-pill").textContent);
  check("bouton = Arrêter", $("#btn-monitor").textContent === "Arrêter");
  check("cycles >= 1", await waitFor(() => Number($("#stat-cycles").textContent) >= 1));
  check("panneau surveillance rempli", $("#dash-monitor").children.length >= 6);

  console.log("Analyse de liens (+ test XSS)");
  nav("scan");
  check("vue scan visible", $("#view-scan").hidden === false && $("#view-dashboard").hidden === true);
  $("#link-input").value = "http://paypal.com@secure-login.example.tk/<img src=x onerror=window.__xss=1>\nhttps://docs.python.org/3/";
  click("#btn-scan-links");
  check("résultats de liens", await waitFor(() => $("#scan-results").querySelectorAll(".panel").length === 2));
  const txt = $("#scan-results").textContent;
  check("badge Risque élevé", txt.includes("Risque élevé"));
  check("badge Aucun indicateur", txt.includes("Aucun indicateur"));
  check("actions recommandées affichées", txt.includes("Actions recommandées") && txt.includes("Ne pas ouvrir ce lien"));
  check("pas d'injection HTML (XSS)", $("#scan-results img") === null && window.__xss === undefined);
  check("le texte brut de l'URL est affiché", txt.includes("<img src=x"));

  console.log("Mise en page : marque, console, onglets, Android");
  check("marque Mougle Protect", $(".brand b").textContent === "Mougle Protect" && doc.title.includes("Mougle Protect"));
  check("titre de page = Analyser", $("#page-title").textContent === "Analyser");
  const log = $("#console-log").textContent;
  check("console : action lancée tracée", log.includes("▶ Analyser les liens") && log.includes("POST /api/scan/links"), log.slice(-300));
  check("console : bilan des résultats", log.includes("Bilan : 2 élément(s)") && log.includes("1 risque élevé"));
  check("console : ligne d'erreur pour un risque élevé", $("#console-log .cl.err") !== null);
  click('#scan-tabs button[data-tab="file"]');
  check("onglet Fichier affiché seul", $('.tab-panel[data-tab="file"]').hidden === false && $('.tab-panel[data-tab="links"]').hidden === true);
  click('#scan-tabs button[data-tab="links"]');
  click("#console-clear");
  check("console effacée", $("#console-log").children.length === 0);
  click("#console-close");
  check("console fermée (ordinateur)", $(".app").classList.contains("console-hidden"));
  click("#console-toggle");
  check("console rouverte", !$(".app").classList.contains("console-hidden"));
  window.matchMedia = () => ({ matches: true });
  click("#console-toggle");
  check("tiroir console ouvert (mobile)", $("#console").classList.contains("open"));
  click("#console-close");
  check("tiroir console fermé (mobile)", !$("#console").classList.contains("open"));
  delete window.matchMedia;
  click("#results-clear");
  check("résultats effacés", $("#scan-results").textContent.includes("Aucune analyse lancée"));
  check("CSS adaptatif Android", (await (await fetch(BASE + "/static/style.css")).text()).includes("@media (max-width: 820px)"));
  check("manifeste PWA", (await (await fetch(BASE + "/manifest.webmanifest")).json()).name === "Mougle Protect");

  console.log("Analyse de chemin");
  $("#path-input").value = (process.env.UI_SAMPLES || "/tmp/e2e/samples");
  click("#btn-scan-path");
  check("résumé de dossier", await waitFor(() => $("#scan-results").textContent.includes("2 fichier(s) analysé(s), 1 à vérifier")), $("#scan-results").textContent.slice(0, 200));
  check("double extension signalée", $("#scan-results").textContent.includes("extension de document"));
  $("#path-input").value = "/chemin/inexistant";
  click("#btn-scan-path");
  check("erreur 404 affichée en toast", await waitFor(() => $("#toast").hidden === false && $("#toast").textContent.includes("introuvable")));

  console.log("Applications actives");
  click("#btn-scan-running");
  check("applications actives analysées", await waitFor(() => $("#scan-results").textContent.includes("Applications en cours d'exécution"), 15000));

  console.log("Retours utilisateur et entraînement");
  check("boutons de retour sur les résultats", $("#scan-results .fb button") !== null);
  $("#scan-results .fb button").click();
  check("retour enregistré (console)", await waitFor(() => $("#console-log").textContent.includes("Retour utilisateur enregistré")));
  nav("training");
  check("page Entraînement affichée", $("#view-training").hidden === false && $("#page-title").textContent === "Données et entraînement");
  check("statut chargé", await waitFor(() => $("#tr-data").textContent.includes("Échantillons malveillants")));
  check("le retour est compté comme échantillon", await waitFor(() => /Échantillonsmalveillants1/.test($("#tr-data").textContent.replace(/\s+/g, ""))));
  $("#hash-text").value = "a".repeat(64) + "\n" + "b".repeat(64);
  click("#btn-hashes");
  check("import de hachages (console)", await waitFor(() => $("#console-log").textContent.includes("2 trouvé(s), 2 ajouté(s)")));
  click("#btn-train");
  check("entraînement refusé faute de données", await waitFor(() => $("#toast").hidden === false && $("#toast").textContent.includes("insuffisantes"), 15000), $("#toast").textContent);
  check("entraînement auto activé par défaut", $("#tr-auto").checked === true);
  check("aucun modèle pour l'instant", $("#tr-models").textContent.includes("Aucun modèle"));
  nav("alerts");

  console.log("Données, EMBER et services en ligne");
  check("bandeau d'état présent", $("#status-title").textContent.length > 0);
  click('#train-tabs button[data-tab="datasets"]');
  check("onglet Jeux de données affiché", $('#view-training .tab-panel[data-tab="datasets"]').hidden === false
        && $('#view-training .tab-panel[data-tab="ember"]').hidden === true);
  check("liste des jeux de données", await waitFor(() => $("#ds-list").textContent.includes("BODMAS") && $("#ds-list").textContent.includes("theZoo")));
  click('#train-tabs button[data-tab="intel"]');
  check("compteurs des menaces connues", await waitFor(() => $("#intel-counts").textContent.includes("Empreintes malveillantes")));
  click('#train-tabs button[data-tab="ember"]');
  check("état du modèle EMBER", await waitFor(() => $("#em-status").textContent.includes("État")));
  check("aucun modèle EMBER ici", $("#em-models").textContent.includes("Aucun modèle"));
  $("#url-text").value = "http://evil.example/a\nhttp://evil.example/b";
  click("#btn-urls");
  check("import de liens (console)", await waitFor(() => $("#console-log").textContent.includes("2 liens")));
  nav("connections");
  check("page Services en ligne", $("#view-connections").hidden === false && $("#page-title").textContent === "Services en ligne");
  check("cinq services listés", await waitFor(() => doc.querySelectorAll("#on-providers .provider").length === 5));
  check("interrupteur général éteint par défaut", $("#on-master").checked === false);
  doc.querySelector('#on-providers input[data-key="abusech"]').value = "CLE-DE-TEST-1234";
  $("#on-master").checked = true;
  click("#btn-on-save");
  check("réglages enregistrés", await waitFor(() => $("#console-log").textContent.includes("Services en ligne autorisés")));
  check("la clé n'est jamais réaffichée", await waitFor(() => !doc.body.innerHTML.includes("CLE-DE-TEST-1234")
        && (doc.querySelector('#on-providers input[data-key="abusech"]').placeholder || "").includes("••••1234")));
  nav("scan");
  $("#link-input").value = "http://evil.example/a";
  click("#btn-scan-links");
  check("lien reconnu par la liste locale", await waitFor(() => $("#scan-results").textContent.includes("figure dans la liste")), $("#scan-results").textContent.slice(0, 300));
  check("niveau critique affiché", $("#scan-results").textContent.includes("Risque élevé"));
  nav("alerts");

  console.log("Alertes");
  nav("alerts");
  check("alertes listées", await waitFor(() => $("#alerts-list").querySelectorAll(".item").length >= 2));
  const before = Number($("#nav-alert-count").textContent);
  check("compteur d'alertes dans la navigation", before >= 2 && $("#nav-alert-count").hidden === false);
  $("#alerts-list .btn").dispatchEvent(new window.Event("click", { bubbles: true }));
  check("acquittement fait baisser le compteur", await waitFor(() => Number($("#nav-alert-count").textContent) === before - 1 || $("#nav-alert-count").hidden));
  $("#alert-level").value = "RISQUE_ELEVE";
  $("#alert-level").dispatchEvent(new window.Event("change"));
  check("filtre par niveau", await waitFor(() => [...$("#alerts-list").querySelectorAll(".badge")].every((b) => b.textContent === "Risque élevé")));

  console.log("Processus / réseau / historique");
  nav("processes");
  check("tableau des processus rempli", await waitFor(() => $("#proc-table tbody").children.length > 3));
  check("compteur de processus", /\d+ processus/.test($("#proc-count").textContent));
  nav("network");
  check("vue réseau rendue", await waitFor(() => $("#net-note").textContent.length > 0));
  nav("history");
  check("historique listé", await waitFor(() => $("#history-list .item .btn") !== null));
  $("#history-list .item .btn").dispatchEvent(new window.Event("click", { bubbles: true }));
  check("détail d'une analyse", await waitFor(() => $("#history-detail .panel") !== null));

  console.log("Contrôle de la surveillance");
  nav("dashboard");
  click("#btn-monitor");
  check("arrêt via l'interface", await waitFor(() => $("#monitor-pill").textContent === "Surveillance arrêtée", 15000));
  click("#btn-monitor");
  check("redémarrage via l'interface", await waitFor(() => $("#monitor-pill").textContent === "Surveillance active", 8000));
  click("#btn-run-once");
  check("cycle manuel (toast)", await waitFor(() => $("#toast").textContent.includes("Cycle terminé"), 15000));

  check("aucune erreur JavaScript", errors.length === 0, JSON.stringify(errors));
  console.log(`\n${passed} vérifications réussies` + (process.exitCode ? " — ECHECS" : ""));
  process.exit(process.exitCode || 0);
})();
