"""Service de surveillance continue : orchestre collecte, analyse, alertes."""

import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from cubernoyau.alerts.alert_manager import AlertManager
from cubernoyau.analysis.application_analyzer import analyze_application
from cubernoyau.analysis.behavior_analyzer import ProcessBehaviorAnalyzer
from cubernoyau.analysis.file_activity_monitor import FileActivityMonitor
from cubernoyau.analysis.network_analyzer import analyze_connections
from cubernoyau.collectors.network_collector import collect_connections
from cubernoyau.collectors.process_collector import collect_processes
from cubernoyau.config import settings
from cubernoyau.detection.decision_engine import decide
from cubernoyau.detection.risk_scorer import score_indicators
from cubernoyau.features.extractor import extract_features
from cubernoyau.intel import loaders
from cubernoyau.intel.online.manager import OnlineIntel
from cubernoyau.intel.store import IntelStore
from cubernoyau.models.ember_classifier import EmberClassifier
from cubernoyau.models.file_classifier import FileClassifier
from cubernoyau.models.model_manager import ProcessAnomalyModel
from cubernoyau.training.ember_model import VectorStore
from cubernoyau.training.service import TrainingService
from cubernoyau.storage.database import Database

from server.scans import ScanService, finalize


class MonitorService:
    """Assemble tous les composants : surveillance, analyses, renseignement, entrainement.

    `online_transport` (tests) remplace l'acces reseau des API externes.
    """

    def __init__(self, db: Database, watch_dirs=None, cooldown=None, online_transport=None):
        self.db = db
        self.alerts = AlertManager(db, cooldown)
        self.classifier = FileClassifier(db)               # modele Cubernoyau (tout type de fichier)
        self.ember = EmberClassifier()                     # modele EMBER (fichiers Windows)
        self.intel = IntelStore(db)                        # listes locales d'empreintes et de liens
        self.online = OnlineIntel(db, self.intel, online_transport)   # API externes (opt-in)
        self.vectors = VectorStore(db)                     # vecteurs EMBER de vos fichiers
        self.training = TrainingService(db, self.classifier, vectors=self.vectors)
        self.training.classifier_ember_reload = self.ember.reload
        self.scans = ScanService(db, self.alerts, self.classifier, self.ember, self.intel, self.online)

        self.model = ProcessAnomalyModel()
        self.behavior = ProcessBehaviorAnalyzer()
        self.activity = FileActivityMonitor(
            settings.get_watch_dirs() if watch_dirs is None else watch_dirs)

        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self.interval = settings.MONITOR_INTERVAL
        self.cycles = 0
        self.last_cycle_at = None
        self.last_error = None
        self.latest_processes = []
        self.latest_network = {"available": True, "connections": [],
                               "findings": []}
        self.latest_activity = None
        self._analyzed_apps = {}
        self._exe_results = {}       # executable -> derniere analyse statique

    # ---- un cycle de surveillance (appelable directement dans les tests)
    def run_cycle(self):
        """Un cycle : collecte processus/reseau/fichiers, analyse, correlation, alertes."""
        started = time.monotonic()
        processes = collect_processes(include_cmdline=True)
        features = [extract_features(p) for p in processes]
        anomalies = self.model.score(features)
        behavior = self.behavior.analyze(processes)

        analyzed_now = self._analyze_new_apps(processes)
        net = collect_connections(processes)
        findings = analyze_connections(net["connections"])
        by_pid = {}
        for finding in findings:
            by_pid.setdefault(finding.get("pid"), []).extend(finding["indicators"])

        view = []
        for proc, anomaly in zip(processes, anomalies):
            indicators = list(behavior.get(proc.get("pid"), []))
            # Correlation : analyse statique du programme + connexions reseau
            static = self._exe_results.get(proc.get("executable"))
            if static and static["risk"]["level"] != "AUCUN_INDICATEUR_DETECTE":
                indicators += [i for i in static["risk_indicators"]
                               if i["severity"] != "info"]
            indicators += by_pid.get(proc.get("pid"), [])
            seen = set()
            indicators = [i for i in indicators
                          if not (i["code"] in seen or seen.add(i["code"]))]
            if anomaly and anomaly["anomaly"]:
                indicators.append({
                    "code": "STATISTICAL_ANOMALY", "severity": "low",
                    "reason": "Profil statistiquement inhabituel par "
                              "rapport aux autres processus (Isolation Forest)."})
            risk = score_indicators(indicators)
            item = {
                "pid": proc.get("pid"), "name": proc.get("name"),
                "parent_name": proc.get("parent_name"),
                "username": proc.get("username"),
                "executable": proc.get("executable"),
                "cpu_percent": proc.get("cpu_percent"),
                "memory_rss_bytes": proc.get("memory_rss_bytes"),
                "num_threads": proc.get("num_threads"),
                "anomaly": bool(anomaly and anomaly["anomaly"]),
                "anomaly_score": anomaly["score"] if anomaly else None,
                "risk": risk, "indicators": indicators,
            }
            view.append(item)
            if risk["level"] != "AUCUN_INDICATEUR_DETECTE":
                self.alerts.raise_alert(
                    "process", f"{item['name']} (PID {item['pid']})", risk,
                    {k: item[k] for k in ("pid", "name", "parent_name",
                                          "executable", "indicators")},
                    dedupe_key=f"proc:{(item['name'] or '').lower()}:"
                               f"{item['executable']}:"
                               f"{','.join(sorted(i['code'] for i in indicators))}",
                    decision=decide("process", risk))

        for finding in findings:
            risk = score_indicators(finding["indicators"])
            finding["risk"] = risk
            if risk["level"] != "AUCUN_INDICATEUR_DETECTE":
                self.alerts.raise_alert(
                    "network",
                    f"{finding['process']} (PID {finding['pid']}) : connexions externes",
                    risk, finding,
                    dedupe_key=f"net:{finding['executable'] or finding['process']}:"
                               f"{','.join(sorted(i['code'] for i in finding['indicators']))}",
                    decision=decide("network", risk))

        activity = self.activity.scan()
        activity["risk"] = score_indicators(activity["indicators"])
        if activity["indicators"]:
            self.alerts.raise_alert(
                "file_activity", "Activite inhabituelle sur les fichiers",
                activity["risk"], activity,
                dedupe_key="fa:" + ",".join(
                    sorted(i["code"] for i in activity["indicators"])),
                decision=decide("file_activity", activity["risk"]))

        self.training.maybe_auto_train()
        self.training.maybe_auto_train_ember()

        with self._lock:
            self.latest_processes = view
            self.latest_network = {
                "available": net["available"], "error": net["error"],
                "connections": net["connections"], "findings": findings}
            self.latest_activity = activity
            self.cycles += 1
            self.last_cycle_at = datetime.now(timezone.utc).isoformat()
            self.last_error = None

        return {
            "processes": len(view),
            "flagged_processes": sum(
                v["risk"]["level"] != "AUCUN_INDICATEUR_DETECTE" for v in view),
            "statistical_anomalies": sum(v["anomaly"] for v in view),
            "connections": len(net["connections"]),
            "applications_analyzed": analyzed_now,
            "file_activity_baseline": activity["baseline"],
            "duration_seconds": round(time.monotonic() - started, 2),
        }

    SYSTEM_MARKERS = ("\\windows\\", "\\program files", "/usr/", "/bin/",
                      "/lib/", "/sbin/", "/snap/", "/opt/")

    def _analyze_new_apps(self, processes):
        """Analyse profonde des executables jamais vus (hors dossiers systeme d'abord)."""
        exes = sorted({p["executable"] for p in processes if p.get("executable")},
                      key=lambda e: (any(m in e.lower().replace("/", "\\") or m in e.lower()
                                         for m in self.SYSTEM_MARKERS), e))
        done = 0
        for exe in exes:
            if done >= settings.MAX_NEW_APPS_PER_CYCLE:
                break
            try:
                st = Path(exe).stat()
            except OSError:
                continue
            key = (st.st_mtime_ns, st.st_size)
            if self._analyzed_apps.get(exe) == key:
                continue
            self._analyzed_apps[exe] = key
            try:
                self._exe_results[exe] = self.scans._analyze("application", Path(exe))
            except (OSError, ValueError):
                continue
            done += 1
        return done

    # ---- boucle en arriere-plan
    def _loop(self):
        """Boucle du fil de surveillance : un cycle toutes les `interval` secondes jusqu'a l'arret."""
        while not self._stop.is_set():
            try:
                self.run_cycle()
            except Exception as error:  # la surveillance ne doit pas s'arreter
                self.last_error = f"{type(error).__name__}: {error}"
            self._stop.wait(self.interval)

    def start(self, interval=None):
        """Demarre le fil de surveillance (sans effet s'il tourne deja)."""
        if interval:
            self.interval = float(interval)
        if self.running:
            return False
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="cubernoyau-monitor", daemon=True)
        self._thread.start()
        return True

    def stop(self):
        """Arrete le fil de surveillance et attend sa fin."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
        self._thread = None

    @property
    def running(self):
        """True si la surveillance tourne."""
        return bool(self._thread and self._thread.is_alive())

    def status(self):
        """Etat de la surveillance : en marche, intervalle, derniere erreur, derniers cycles."""
        with self._lock:
            return {
                "running": self.running, "interval_seconds": self.interval,
                "cycles": self.cycles, "last_cycle_at": self.last_cycle_at,
                "last_error": self.last_error,
                "watched_directories": self.activity.directories,
            }

    # ---- renseignement : synchronisation des listes du dossier data/threat_intel
    def sync_intel(self, force=False):
        """Importe les listes nouvelles ou modifiees (empreintes, liens). Retourne le rapport."""
        return loaders.sync_intel_folders(self.intel, force=force)

    def sync_intel_async(self):
        """Lance la synchronisation en arriere-plan (au demarrage du serveur)."""
        return self.training.start_job("intel", lambda job: self.sync_intel())
