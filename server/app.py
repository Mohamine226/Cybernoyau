"""API FastAPI de Cubernoyau (a executer en local uniquement)."""

import platform
import secrets
from datetime import datetime
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal, Optional

import io

from fastapi import FastAPI, File, HTTPException, Query, Response, UploadFile
from fastapi import Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from cubernoyau.config import settings
from cubernoyau.intel import loaders
from cubernoyau.storage.database import Database
from cubernoyau.training import datasets as dataset_registry
from cubernoyau.models import ember_classifier

from server.service import MonitorService

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


class LinkScanRequest(BaseModel):
    """Corps de POST /api/scan/links : la liste des liens a analyser."""
    urls: list[str] = Field(..., min_length=1,
                            max_length=settings.MAX_LINKS_PER_REQUEST)


class PathScanRequest(BaseModel):
    """Corps de POST /api/scan/path : chemin local, type d'analyse et recursivite."""
    path: str = Field(..., min_length=1, max_length=1024)
    kind: Literal["file", "application"] = "file"
    recursive: bool = False


class HashImportRequest(BaseModel):
    """Corps de POST /api/training/hashes : texte contenant des empreintes SHA-256."""
    text: str = Field(..., min_length=64, max_length=50_000_000)
    source: str = Field("import", max_length=60)


class FolderIngestRequest(BaseModel):
    """Corps de POST /api/training/ingest-folder : dossier etiquete a ingerer."""
    path: str = Field(..., min_length=1, max_length=1024)
    label: Literal["malware", "benign"]
    recursive: bool = True
    max_files: int = Field(5000, ge=1, le=200000)


class TrainRequest(BaseModel):
    """Corps de POST /api/training/train (modele Cubernoyau)."""
    test_size: float = Field(0.25, ge=0.1, le=0.5)
    activate: bool = False
    wait: bool = False


class AutoTrainRequest(BaseModel):
    """Active ou desactive un reentrainement automatique."""
    enabled: bool


class FeedbackRequest(BaseModel):
    """Retour utilisateur sur une analyse : 'malware' ou 'benign'."""
    scan_id: int
    label: Literal["malware", "benign"]


class OnlineSettingsRequest(BaseModel):
    """Reglages des API externes : interrupteur general, services actifs, cles."""
    master: Optional[bool] = None
    enabled: Optional[dict[str, bool]] = None
    keys: Optional[dict[str, str]] = None


class OnlineCheckRequest(BaseModel):
    """Interrogation manuelle d'un service en ligne : une empreinte ('hash') ou un lien ('url')."""
    kind: Literal["hash", "url"]
    value: str = Field(..., min_length=3, max_length=2000)


class UrlImportRequest(BaseModel):
    """Liste de liens malveillants collee dans l'interface."""
    text: str = Field(..., min_length=8, max_length=50_000_000)
    kind: Literal["malware", "phishing"] = "malware"
    source: str = Field("import", max_length=60)


class EmberTrainRequest(BaseModel):
    """Parametres de l'entrainement EMBER : profil et usage de BODMAS."""
    profile: Literal["rapide", "standard"] = "rapide"
    use_bodmas: bool = True


class EmberActivateRequest(BaseModel):
    """Nom du fichier de modele EMBER a activer."""
    file: str = Field(..., min_length=5, max_length=120)


class MonitorStartRequest(BaseModel):
    """Intervalle (secondes) du cycle de surveillance."""
    interval: Optional[float] = Field(None, ge=2, le=300)


def create_app(service: Optional[MonitorService] = None,
               autostart: Optional[bool] = None,
               access_token: Optional[str] = None) -> FastAPI:
    """Construit l'application FastAPI. `service` et `access_token` sont injectables (tests) ; `autostart` demarre la surveillance."""
    token = settings.ACCESS_TOKEN if access_token is None else access_token
    owns_service = service is None
    if service is None:
        service = MonitorService(Database(settings.DB_PATH))
    do_autostart = settings.AUTOSTART if autostart is None else autostart

    @asynccontextmanager
    async def lifespan(_app):
        """Demarrage : lance la surveillance et la synchronisation des listes ; arret : stoppe proprement."""
        if do_autostart:
            service.start()
            service.sync_intel_async()      # importe les listes de data/threat_intel en arriere-plan
        yield
        service.stop()
        if owns_service:
            service.db.close()

    app = FastAPI(title="Mougle Protect (Cubernoyau)", version="1.0.0", lifespan=lifespan)
    # Sans jeton : seules les adresses locales (protection contre le "DNS
    # rebinding"). Avec jeton (mode reseau local / Android) : toute adresse,
    # mais chaque appel /api doit presenter le jeton.
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"] if token else ["127.0.0.1", "localhost", "testserver"])

    @app.middleware("http")
    async def require_token(request: Request, call_next):
        """Exige l'en-tete X-Access-Token sur /api/* quand un jeton est configure (mode telephone)."""
        if token and request.url.path.startswith("/api/"):
            given = request.headers.get("x-access-token", "")
            if not secrets.compare_digest(given.encode(), token.encode()):
                return JSONResponse({"detail": "Code d'acces manquant ou invalide."},
                                    status_code=401)
        return await call_next(request)

    app.state.service = service

    # ---------- etat
    @app.get("/api/health")
    def health():
        """Verifie que le serveur repond."""
        return {"status": "ok", "platform": platform.system()}

    @app.get("/api/status")
    def status():
        """Etat global : surveillance, compteurs d'alertes, plateforme."""
        return {
            "monitor": service.status(),
            "counts": service.db.counts(),
            "platform": platform.system(),
            "signature_check": platform.system() == "Windows",
        }

    # ---------- surveillance
    @app.post("/api/monitor/start")
    def monitor_start(body: MonitorStartRequest = MonitorStartRequest()):
        """Demarre la surveillance continue."""
        started = service.start(body.interval)
        return {"started": started, **service.status()}

    @app.post("/api/monitor/stop")
    def monitor_stop():
        """Arrete la surveillance continue."""
        service.stop()
        return service.status()

    @app.post("/api/monitor/run-once")
    def monitor_run_once():
        """Lance immediatement un cycle de verification."""
        return service.run_cycle()

    @app.get("/api/processes")
    def processes(only_flagged: bool = False):
        """Derniers processus observes avec leur niveau de risque."""
        items = service.latest_processes
        if only_flagged:
            items = [p for p in items
                     if p["risk"]["level"] != "AUCUN_INDICATEUR_DETECTE"]
        items = sorted(items, key=lambda p: (-p["risk"]["score"],
                                             p["anomaly_score"] or 0))
        return {"count": len(items), "processes": items}

    @app.get("/api/network")
    def network():
        """Connexions reseau actives et constats par processus."""
        return service.latest_network

    @app.get("/api/file-activity")
    def file_activity():
        """Dernier bilan de l'activite des fichiers (modifications massives)."""
        return service.latest_activity or {"baseline": True, "indicators": []}

    # ---------- alertes
    @app.get("/api/alerts")
    def list_alerts(level: Optional[str] = None,
                    acknowledged: Optional[bool] = None,
                    limit: int = Query(200, ge=1, le=1000)):
        """Liste les alertes, filtrables par niveau et par statut."""
        return {"alerts": service.alerts.list(
            level=level, acknowledged=acknowledged, limit=limit)}

    @app.post("/api/alerts/{alert_id}/ack")
    def ack_alert(alert_id: int):
        """Marque une alerte comme traitee (acquittee)."""
        if not service.alerts.acknowledge(alert_id):
            raise HTTPException(404, "Alerte introuvable.")
        return {"acknowledged": True, "id": alert_id}

    # ---------- analyses
    @app.post("/api/scan/links")
    def scan_links(body: LinkScanRequest):
        """Analyse des liens : forme, listes locales et services en ligne (si actives)."""
        for url in body.urls:
            if len(url) > 2048:
                raise HTTPException(422, "URL trop longue (max 2048).")
        return {"results": service.scans.scan_links(body.urls)}

    async def _upload(kind, file: UploadFile):
        """Lit un fichier televerse par blocs et l'analyse sans jamais l'executer."""
        try:
            return service.scans.scan_upload(
                kind, file.filename, file.file,
                settings.MAX_UPLOAD_MB * 1024 * 1024 or None)
        except ValueError as error:
            raise HTTPException(413, str(error))

    @app.post("/api/scan/file")
    async def scan_file(file: UploadFile = File(...)):
        """Analyse un fichier televerse comme simple fichier."""
        return await _upload("file", file)

    @app.post("/api/scan/application")
    async def scan_application(file: UploadFile = File(...)):
        """Analyse un fichier televerse comme application (signature, PE, emplacement)."""
        return await _upload("application", file)

    @app.post("/api/scan/path")
    def scan_path(body: PathScanRequest):
        """Analyse un fichier ou dossier de l'ordinateur (jamais execute)."""
        try:
            return service.scans.scan_path(body.kind, body.path, body.recursive)
        except FileNotFoundError as error:
            raise HTTPException(404, str(error))
        except (ValueError, PermissionError, OSError) as error:
            raise HTTPException(400, str(error))

    @app.post("/api/scan/running-applications")
    def scan_running(limit: int = Query(40, ge=1, le=200)):
        """Analyse statique des executables des processus en cours."""
        if not service.cycles:
            service.run_cycle()
        paths = [p["executable"] for p in service.latest_processes
                 if p.get("executable")]
        return service.scans.scan_running_applications(paths, limit)

    # ---------- entrainement
    training = service.training

    def _job_or_400(func):
        """Execute `func` et convertit ses erreurs en reponses HTTP (404 introuvable, 400 invalide)."""
        try:
            return func()
        except FileNotFoundError as error:
            raise HTTPException(404, str(error))
        except (ValueError, OSError) as error:
            raise HTTPException(400, str(error))

    @app.get("/api/training/status")
    def training_status():
        """Etat du modele Cubernoyau : donnees, modeles, taches en cours."""
        return training.status()

    @app.post("/api/training/hashes")
    def training_hashes(body: HashImportRequest):
        """Ajoute des empreintes malveillantes collees dans l'interface."""
        found, added = training.import_hashes(
            body.text.splitlines(), source=body.source)
        return {"found": found, "added": added, "known_hashes": service.db.count_known_hashes()}

    @app.post("/api/training/hashes/upload")
    def training_hashes_upload(file: UploadFile = File(...)):
        """Ajoute des empreintes depuis un fichier (TXT/CSV), lu en flux."""
        lines = io.TextIOWrapper(file.file, encoding="utf-8", errors="ignore")
        found, added = training.import_hashes(lines, source=f"fichier:{(file.filename or '')[:40]}")
        return {"found": found, "added": added, "known_hashes": service.db.count_known_hashes()}

    @app.post("/api/training/ingest-folder")
    def training_ingest(body: FolderIngestRequest):
        """Ingere un dossier etiquete (tache de fond)."""
        if not Path(body.path).expanduser().is_dir():
            raise HTTPException(404, f"Dossier introuvable : {body.path}")
        return training.start_job("ingest", lambda job: training.ingest_folder(
            job, body.path, body.label, body.recursive, body.max_files))

    @app.post("/api/training/import-features")
    def training_import_features(file: UploadFile = File(...)):
        """Importe un CSV de caracteristiques exporte d'un autre poste."""
        text = file.file.read().decode("utf-8", errors="ignore")
        return _job_or_400(lambda: training.import_features_csv(text))

    @app.get("/api/training/export")
    def training_export():
        """Exporte le jeu de caracteristiques en CSV (partage sans les fichiers)."""
        return Response(training.export_csv(), media_type="text/csv", headers={
            "Content-Disposition": 'attachment; filename="mougle_protect_dataset.csv"'})

    @app.post("/api/training/train")
    def training_train(body: TrainRequest = TrainRequest()):
        """Entraine le modele Cubernoyau (tache de fond, ou immediat avec wait=true)."""
        if body.wait:
            return _job_or_400(lambda: training.train(
                test_size=body.test_size, force_activate=body.activate))
        if training.job_running("train"):
            raise HTTPException(409, "Un entrainement est deja en cours.")
        return training.start_job("train", lambda job: training.train(
            job, body.test_size, body.activate))

    @app.post("/api/training/activate/{model_id}")
    def training_activate(model_id: int):
        """Active un modele Cubernoyau precedent (retour arriere)."""
        _job_or_400(lambda: training.activate(model_id))
        return {"active_model": service.db.active_model()}

    @app.post("/api/training/auto")
    def training_auto(body: AutoTrainRequest):
        """Active/desactive le reentrainement automatique du modele Cubernoyau."""
        service.db.set_setting("auto_train", "1" if body.enabled else "0")
        return {"auto_train": body.enabled}

    @app.get("/api/training/jobs/{job_id}")
    def training_job(job_id: str):
        """Avancement d'une tache de fond (progression, message, resultat)."""
        job = training.jobs.get(job_id)
        if not job:
            raise HTTPException(404, "Tache introuvable.")
        return job

    @app.post("/api/feedback")
    def feedback(body: FeedbackRequest):
        """Enregistre un retour 'malveillant / sur' : alimente les deux modeles et les listes."""
        scan = service.db.get_scan(body.scan_id)
        if not scan:
            raise HTTPException(404, "Analyse introuvable.")
        report = scan["report"]
        feats = (report.get("deep") or {}).get("features")
        if not feats or not report.get("sha256"):
            raise HTTPException(400, "Retour impossible : cette analyse n'a pas de caracteristiques (ex. lien).")
        training.feedback(report["sha256"], feats, body.label, vector=service.scans.vector_for(body.scan_id))
        if body.label == "benign":
            service.scans.forget(report["sha256"])
        return {"recorded": True, "samples": service.db.sample_counts()}

    # ---------- jeux de donnees et renseignement local
    @app.get("/api/datasets")
    def datasets_status():
        """Etat de chaque jeu de donnees (present ? combien de fichiers ? actions possibles)."""
        return {"datasets": dataset_registry.discover(), "intel": service.intel.counts(),
                "intel_files": service.intel.files()}

    @app.post("/api/datasets/{name}/{action}")
    def dataset_action(name: str, action: str):
        """Lance une action sur un jeu : importer ses empreintes, l'ingerer, entrainer EMBER."""
        if service.training.job_running("ember") or service.training.job_running("ingest"):
            raise HTTPException(409, "Une tache est deja en cours : attendez qu'elle se termine.")

        def folder_job(folder, label):
            """Lance l'ingestion d'un dossier en tache de fond."""
            return service.training.start_job("ingest", lambda job: service.training.ingest_folder(
                job, folder, label, recursive=True, max_files=200000))

        if (name, action) == ("bodmas", "import_intel"):
            def run(job):
                """Convertit les metadonnees BODMAS en listes puis les synchronise."""
                made = loaders.bodmas_to_intel_files()
                return {"listes": made, "synchronisation": service.sync_intel(force=True)}
            return service.training.start_job("intel", run)
        if (name, action) == ("bodmas", "train_ember"):
            return _start_ember_training("rapide", True)
        if (name, action) == ("custom_malware", "ingest_malware"):
            return folder_job(settings.CUSTOM_MALWARE_DIR, "malware")
        if (name, action) == ("custom_benign", "ingest_benign"):
            return folder_job(settings.CUSTOM_BENIGN_DIR, "benign")
        if (name, action) == ("sorel20m", "ingest_sorel"):
            return folder_job(settings.SOREL_DIR / "binaries", "malware")
        if (name, action) == ("thezoo", "ingest_thezoo"):
            return service.training.start_job("ingest", lambda job: service.training.ingest_archives(
                job, settings.THEZOO_DIR / "repo", "malware"))
        raise HTTPException(404, "Action inconnue pour ce jeu de donnees.")

    @app.post("/api/intel/sync")
    def intel_sync(force: bool = False):
        """Re-synchronise les listes de data/threat_intel (empreintes, liens)."""
        return service.training.start_job("intel", lambda job: service.sync_intel(force=force))

    @app.post("/api/intel/urls")
    def intel_urls(body: UrlImportRequest):
        """Ajoute une liste de liens malveillants collee dans l'interface (URLhaus, PhishTank...)."""
        pairs = list(loaders.parse_url_lines(body.text.splitlines(), body.kind))
        added_u, added_h = service.intel.add_urls((u, k, body.source) for u, k in pairs)
        return {"found": len(pairs), "urls_added": added_u, "hosts_added": added_h,
                "counts": service.intel.counts()}

    @app.post("/api/intel/urls/upload")
    def intel_urls_upload(file: UploadFile = File(...), kind: Literal["malware", "phishing"] = "malware"):
        """Ajoute des liens malveillants depuis un fichier (URLhaus, PhishTank...)."""
        lines = io.TextIOWrapper(file.file, encoding="utf-8", errors="ignore")
        pairs = list(loaders.parse_url_lines(lines, kind))
        added_u, added_h = service.intel.add_urls((u, k, f"fichier:{(file.filename or '')[:40]}") for u, k in pairs)
        return {"found": len(pairs), "urls_added": added_u, "hosts_added": added_h,
                "counts": service.intel.counts()}

    # ---------- API externes d'analyse (opt-in)
    @app.get("/api/online/settings")
    def online_settings():
        """Reglages des services en ligne (cles masquees)."""
        return service.online.get_settings()

    @app.post("/api/online/settings")
    def online_update(body: OnlineSettingsRequest):
        """Modifie l'interrupteur general, les services actifs et les cles."""
        return service.online.update_settings(body.master, body.enabled, body.keys)

    @app.post("/api/online/test/{provider}")
    def online_test(provider: str):
        """Teste qu'un service repond et que sa cle est acceptee."""
        return service.online.test(provider)

    @app.post("/api/online/check")
    def online_check(body: OnlineCheckRequest):
        """Interrogation manuelle d'une empreinte ou d'un lien (hors analyse de fichier)."""
        if not service.online.master_enabled():
            raise HTTPException(409, "Les API externes sont desactivees (page Connexions).")
        if body.kind == "hash":
            if not loaders.SHA256_RE.fullmatch(body.value.strip()):
                raise HTTPException(400, "Empreinte SHA-256 invalide (64 caracteres hexadecimaux).")
            return service.online.check_hash(body.value.strip())
        return service.online.check_url(body.value.strip())

    # ---------- modele EMBER
    def _start_ember_training(profile, use_bodmas):
        """Entraine le modele EMBER en arriere-plan (BODMAS + vos vecteurs) puis le recharge."""
        from cubernoyau.training import ember_model
        try:
            import lightgbm  # noqa: F401
        except ImportError:
            raise HTTPException(400, "LightGBM n'est pas installe : pip install lightgbm")

        def run(job):
            """Entraine EMBER, recharge le modele actif et note le nombre de vecteurs utilises."""
            meta = ember_model.train_from_sources(
                service.db, profile=profile, use_bodmas=use_bodmas,
                progress=lambda i, n, m: job.update(progress=i, total=n, message=m))
            service.ember.reload()
            service.db.set_setting("ember.last_vectors", str(service.vectors.counts()["total"]))
            return {"model": meta["name"], "thresholds": meta["thresholds"], "metrics": meta["metrics"],
                    "n_total": meta["n_total"]}
        return service.training.start_job("ember", run)

    @app.get("/api/ember/status")
    def ember_status():
        """Etat du modele EMBER : actif, modeles enregistres, vos vecteurs, BODMAS."""
        return {"available": service.ember.available, "error": service.ember.error,
                "active": service.ember.info(), "models": ember_classifier.list_models(),
                "your_vectors": service.vectors.counts(),
                "bodmas_present": (settings.BODMAS_DIR / "bodmas.npz").is_file(),
                "auto_train": service.db.get_setting("auto_train_ember", "1") == "1"}

    @app.post("/api/ember/train")
    def ember_train(body: EmberTrainRequest = EmberTrainRequest()):
        """Lance l'entrainement du modele EMBER en tache de fond."""
        if service.training.job_running("ember"):
            raise HTTPException(409, "Un entrainement EMBER est deja en cours.")
        return _start_ember_training(body.profile, body.use_bodmas)

    @app.post("/api/ember/activate")
    def ember_activate(body: EmberActivateRequest):
        """Choisit le modele EMBER actif (permet un retour arriere)."""
        try:
            ember_classifier.set_active(body.file)
        except FileNotFoundError as error:
            raise HTTPException(404, str(error))
        service.ember.reload()
        return {"active": service.ember.info()}

    @app.post("/api/ember/auto")
    def ember_auto(body: AutoTrainRequest):
        """Active/desactive le reentrainement automatique d'EMBER."""
        service.db.set_setting("auto_train_ember", "1" if body.enabled else "0")
        return {"auto_train": body.enabled}

    # ---------- historique et rapport
    @app.get("/api/scans")
    def list_scans(limit: int = Query(100, ge=1, le=500)):
        """Historique des analyses."""
        return {"scans": service.db.list_scans(limit)}

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: int):
        """Detail complet d'une analyse enregistree."""
        scan = service.db.get_scan(scan_id)
        if not scan:
            raise HTTPException(404, "Analyse introuvable.")
        return scan

    @app.get("/api/report")
    def report():
        """Rapport complet exportable : etat, alertes, analyses."""
        return {
            "generated_at": datetime.now().astimezone().isoformat(),
            "counts": service.db.counts(),
            "monitor": service.status(),
            "alerts": service.alerts.list(limit=500),
            "scans": service.db.list_scans(200),
            "notice": ("Rapport d'observations : aucun element n'a ete "
                       "supprime, bloque ou modifie par Cubernoyau."),
        }

    # ---------- frontend
    @app.get("/", include_in_schema=False)
    def index():
        """Sert la page d'accueil de l'interface."""
        return FileResponse(FRONTEND_DIR / "index.html")

    @app.get("/sw.js", include_in_schema=False)
    def service_worker():
        """Sert le service worker a la racine (necessaire pour l'installation en application)."""
        return FileResponse(FRONTEND_DIR / "sw.js", media_type="application/javascript",
                            headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"})

    @app.get("/manifest.webmanifest", include_in_schema=False)
    def manifest():
        """Sert le manifeste d'application web (installation sur Android)."""
        return FileResponse(FRONTEND_DIR / "manifest.webmanifest",
                            media_type="application/manifest+json")

    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
    return app


app = create_app()
