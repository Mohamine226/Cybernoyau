"""Analyses a la demande : fichiers, applications, liens, dossiers.

C'est ici que les differentes briques du noyau sont ASSEMBLEES pour un element analyse :

    analyse locale (nom, signature, emplacement, APK)         cubernoyau.analysis.*
      + moteur profond (contenu, PE, capacites, regles)        deep_analyzer
      + listes locales (empreintes / liens connus)             cubernoyau.intel.store
      + modele EMBER (fichiers Windows)                        models.ember_classifier
      + modele Cubernoyau (tout type de fichier)               models.file_classifier
      + API externes, si activees (MalwareBazaar, VirusTotal)  intel.online
    ---> une liste unique d'INDICATEURS -> score de risque -> decision -> alerte.

Le fichier analyse n'est jamais execute ; un fichier televerse est supprime des que
l'analyse est terminee.
"""

import re
import shutil
import tempfile
import time
from collections import OrderedDict
from pathlib import Path

from cubernoyau.alerts.alert_manager import AlertManager
from cubernoyau.analysis.apk_analyzer import analyze_apk
from cubernoyau.analysis.application_analyzer import analyze_application
from cubernoyau.analysis.deep_analyzer import deep_analyze
from cubernoyau.analysis.file_analyzer import analyze_file
from cubernoyau.analysis.link_analyzer import analyze_url
from cubernoyau.config import settings
from cubernoyau.detection.decision_engine import decide
from cubernoyau.detection.risk_scorer import max_level, score_indicators
from cubernoyau.storage.database import Database

# Nombre d'analyses recentes dont on garde le vecteur EMBER en memoire (pour les retours utilisateurs).
VECTOR_CACHE_SIZE = 300


def finalize(source, result):
    """Calcule le score unifie et la decision ; remplace l'evaluation propre a chaque module."""
    risk = score_indicators(result.get("risk_indicators", []))
    result["risk"] = risk
    result["assessment"] = risk["level"]
    result["decision"] = decide(source, risk)
    return result


def safe_name(name):
    """Nom de fichier televerse nettoye (aucun chemin, aucun caractere special)."""
    base = Path(name or "fichier").name
    base = re.sub(r"[^\w.\- ()]", "_", base)[:120].strip(" .")
    return base or "fichier"


class ScanService:
    """Assemble toutes les briques d'analyse pour un fichier, une application ou un lien (voir l'en-tete du module)."""
    def __init__(self, db: Database, alerts: AlertManager, classifier=None,
                 ember=None, intel=None, online=None):
        self.db = db
        self.alerts = alerts
        self.classifier = classifier       # modele Cubernoyau (RandomForest)
        self.ember = ember                 # modele EMBER (LightGBM) ou None
        self.intel = intel                 # listes locales (IntelStore) ou None
        self.online = online               # API externes (OnlineIntel) ou None
        self._vectors = OrderedDict()      # scan_id -> (sha256, vecteur EMBER)

    # ------------------------------------------------------------------ enregistrement
    def _record(self, kind, target, result, key):
        """Enregistre l'analyse dans l'historique et leve une alerte si necessaire."""
        risk = result["risk"]
        scan_id = self.db.add_scan(kind, target, risk["level"], risk["score"], result)
        self.alerts.raise_alert(
            kind, f"{kind} : {target}"[:200], risk, {"scan_id": scan_id, "target": target},
            dedupe_key=f"scan:{key}", decision=result["decision"])
        result["scan_id"] = scan_id
        return result

    def forget(self, sha256):
        """Retour 'sain' : on oublie le delai anti-spam d'alerte de ce fichier."""
        for kind in ("file", "application"):
            self.alerts._last_seen.pop(f"scan:{kind}:{sha256}", None)

    def vector_for(self, scan_id):
        """Vecteur EMBER d'une analyse recente (pour un retour utilisateur), ou None."""
        item = self._vectors.get(scan_id)
        return item[1] if item else None

    # ------------------------------------------------------------------ liens
    def scan_links(self, urls):
        """Analyse des liens : forme de l'adresse + listes locales + API externes (si activees)."""
        results = []
        deadline = time.monotonic() + 25          # budget total pour les requetes en ligne
        for url in urls:
            url = url.strip()
            if not url:
                continue
            result = analyze_url(url)
            indicators = result.setdefault("risk_indicators", [])
            # 1) listes locales (URLhaus, PhishTank, ThreatFox...) : instantane, hors ligne
            if self.intel is not None:
                hit = self.intel.lookup_url(url)
                if hit:
                    exact = hit["match"] == "url"
                    what = {"phishing": "hameconnage", "c2": "serveur de commande de malware"}.get(
                        hit["kind"], "diffusion de malwares")
                    indicators.append({
                        "code": "KNOWN_MALICIOUS_URL", "severity": "critical" if exact else "high",
                        "reason": f"{'Ce lien' if exact else 'Ce domaine'} figure dans la liste « {hit['source']} » "
                                  f"({what})."})
                    result["local_intel"] = hit
            # 2) API externes (seulement si l'utilisateur les a activees)
            if self.online is not None and self.online.master_enabled():
                online = self.online.check_url(url, budget_seconds=max(1, deadline - time.monotonic()))
                result["online"] = online
                indicators.extend(online["indicators"])
            result = finalize("link", result)
            results.append(self._record("link", url, result, f"link:{url}"))
        return results

    # ------------------------------------------------------------------ fichiers / applications
    def scan_upload(self, kind, original_name, stream, max_bytes):
        """Analyse un fichier televerse : ecrit par blocs dans un dossier temporaire, analyse, supprime."""
        name = safe_name(original_name)
        tmp_dir = Path(tempfile.mkdtemp(prefix="cubernoyau_"))
        target = tmp_dir / name
        try:
            written = 0
            with target.open("wb") as out:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if max_bytes and written > max_bytes:
                        raise ValueError(f"Fichier trop volumineux (limite {settings.MAX_UPLOAD_MB} Mo).")
                    out.write(chunk)
            return self._analyze(kind, target, name, f"televerse/{name}")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _analyze(self, kind, path, display_name=None, display_path=None):
        """Analyse complete d'un fichier sur disque (voir l'en-tete du module pour les etapes)."""
        # --- 1. analyse locale classique
        if kind == "application":
            result = analyze_application(path, display_name, display_path)
        else:
            result = analyze_file(path, display_name, display_path)
        indicators = result.setdefault("risk_indicators", [])
        indicators.extend(analyze_apk(path))

        # --- 2. moteur profond : flux (toute taille), PE, capacites, regles, empreintes connues,
        #        modele Cubernoyau
        known = self.intel.lookup_malware_hash if self.intel else self.db.lookup_hash
        deep = deep_analyze(path, hash_lookup=known, classifier=self.classifier)
        indicators.extend(deep["indicators"])
        sha = deep["sha256"]
        result["sha256"], result["size_bytes"] = sha, deep["size_bytes"]
        result["deep"] = {k: deep[k] for k in (
            "file_type", "md5", "entropy", "partial_scan", "scanned_bytes",
            "capabilities", "families", "pe", "iocs", "features", "ml")}

        # --- 3. liste des fichiers connus comme sains : INFORMATIF seulement (jamais pour masquer un signal)
        if self.intel is not None:
            benign = self.intel.lookup_benign_hash(sha)
            if benign:
                result["deep"]["known_benign"] = benign
                indicators.append({"code": "KNOWN_BENIGN_HASH", "severity": "info",
                                   "reason": f"Cette empreinte figure dans la liste de fichiers sains « {benign} »."})

        # --- 4. modele EMBER (fichiers Windows uniquement)
        vector = None
        if self.ember is not None and deep["file_type"] == "pe":
            result["deep"]["ember"] = {"available": self.ember.available, "error": self.ember.error}
            scored = self.ember.score_file(path) if self.ember.available else None
            if scored is not None:
                vector, probability = scored
                level = self.ember.severity(probability)
                info = self.ember.info()
                result["deep"]["ember"].update({"probability": round(probability, 4), "severity": level, **info})
                if level:
                    indicators.append({
                        "code": "ML_EMBER_MALWARE_PROBABILITY", "severity": level,
                        "reason": (f"Le modele EMBER estime a {probability:.0%} la probabilite que ce programme "
                                   f"soit malveillant (seuil « {level} » mesure a l'entrainement ; modele entraine "
                                   f"sur {info.get('n_samples')} fichiers).")})

        # --- 5. API externes (empreinte seulement), si l'utilisateur les a activees
        if self.online is not None and self.online.master_enabled():
            online = self.online.check_hash(sha)
            result["online"] = online
            indicators.extend(online["indicators"])

        # --- 6. score unifie, historique, alerte
        result = finalize(kind, result)
        record = self._record(kind, display_path or str(path), result, f"{kind}:{sha}")
        if vector is not None:                       # pour un eventuel retour utilisateur
            self._vectors[record["scan_id"]] = (sha, vector)
            while len(self._vectors) > VECTOR_CACHE_SIZE:
                self._vectors.popitem(last=False)
        return record

    # ------------------------------------------------------------------ chemins locaux
    def scan_path(self, kind, raw_path, recursive=False):
        """Analyse un fichier ou un dossier de l'ordinateur (jamais execute)."""
        path = Path(raw_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"Chemin introuvable : {raw_path}")
        path = path.resolve()

        if path.is_file():
            return {"type": "file", "result": self._analyze(kind, path)}
        if not path.is_dir():
            raise ValueError("Le chemin n'est ni un fichier ni un dossier.")

        iterator = path.rglob("*") if recursive else path.iterdir()
        results, errors, truncated = [], [], False
        for item in iterator:
            if not item.is_file() or item.is_symlink():
                continue
            if len(results) >= settings.MAX_DIRECTORY_FILES:
                truncated = True
                break
            try:
                results.append(self._analyze(kind, item))
            except (OSError, ValueError) as error:
                errors.append({"file_path": str(item), "error": str(error)})

        levels = [r["risk"]["level"] for r in results]
        overall = max_level(*levels) if levels else "AUCUN_INDICATEUR_DETECTE"
        return {
            "type": "directory", "directory": str(path), "files_examined": len(results),
            "files_to_review": sum(r["risk"]["level"] != "AUCUN_INDICATEUR_DETECTE" for r in results),
            "overall_level": overall, "truncated": truncated, "errors": errors, "results": results,
            "notice": "Aucun fichier n'a ete execute, ouvert, supprime ou modifie.",
        }

    def scan_running_applications(self, paths_provider, limit=40):
        """Analyse statique des executables fournis (processus en cours)."""
        paths = sorted(set(paths_provider))[:limit]
        applications, errors = [], []
        for exe in paths:
            try:
                applications.append(self._analyze("application", Path(exe)))
            except (OSError, ValueError) as error:
                errors.append({"file_path": exe, "error": str(error)})
        levels = [a["risk"]["level"] for a in applications]
        return {
            "applications_examined": len(applications),
            "to_review": sum(level != "AUCUN_INDICATEUR_DETECTE" for level in levels),
            "overall_level": max_level("AUCUN_INDICATEUR_DETECTE", *levels),
            "applications": applications, "errors": errors,
            "notice": "Aucune application n'a ete executee, arretee ou modifiee.",
        }
