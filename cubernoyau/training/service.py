"""Entrainement : hachages connus, echantillons etiquetes, retours utilisateurs.

Seules des caracteristiques numeriques sont conservees (pas les fichiers).
Les modeles sont crees localement ; on n'importe jamais de modele externe
(un fichier de modele peut executer du code a son chargement) : on partage
des jeux de donnees CSV de caracteristiques, jamais des modeles.
"""

import csv
import io
import os
import re
import shutil
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
import joblib

from cubernoyau.analysis.deep_analyzer import FEATURE_NAMES, deep_analyze
from cubernoyau.config import settings
from cubernoyau.features import ember_v2

HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


class TrainingError(ValueError):
    """Donnees insuffisantes ou invalides pour entrainer."""
    pass


class TrainingService:
    """Entrainement du modele "Cubernoyau" (RandomForest, tout type de fichier) et collecte
    des donnees qui servent AUSSI au modele EMBER (vecteurs des fichiers Windows).

    Sources de donnees :
      - dossiers etiquetes (ingest_folder) et archives protegees comme theZoo (ingest_archives) ;
      - retours utilisateurs "C'est malveillant / C'est sur" (feedback) ;
      - import / export CSV de caracteristiques (partage entre postes, sans les fichiers).
    Les fichiers eux-memes ne sont JAMAIS conserves : seuls des nombres le sont.
    """

    def __init__(self, db, classifier, models_dir=None, vectors=None):
        self.db = db
        self.classifier = classifier
        self.vectors = vectors                   # VectorStore des vecteurs EMBER (optionnel)
        self.models_dir = Path(models_dir or settings.MODELS_DIR)
        self.jobs = {}
        self._lock = threading.Lock()

    # ---------- taches en arriere-plan
    def start_job(self, kind, func):
        """Lance `func(job)` dans un fil d'execution ; `job` expose progression et resultat a l'interface."""
        job = {"id": uuid.uuid4().hex[:10], "kind": kind, "status": "running",
               "progress": 0, "total": 0, "message": "", "result": None,
               "started_at": datetime.now(timezone.utc).isoformat()}
        with self._lock:
            self.jobs[job["id"]] = job
            for old in sorted(self.jobs)[:-40]:
                self.jobs.pop(old, None)

        def run():
            try:
                job["result"] = func(job)
                job["status"] = "done"
            except Exception as error:
                job["status"] = "error"
                job["message"] = f"{type(error).__name__}: {error}"

        threading.Thread(target=run, name=f"job-{kind}", daemon=True).start()
        return job

    def job_running(self, kind=None):
        """True si une tache (du genre donne, ou n'importe laquelle) est en cours."""
        return any(j["status"] == "running" and (kind is None or j["kind"] == kind)
                   for j in self.jobs.values())

    # ---------- hachages connus
    def import_hashes(self, lines, label="malware", source="import"):
        """lines : iterable de lignes de texte (TXT ou CSV). Retourne (trouves, ajoutes)."""
        found = added = 0
        batch = []
        for line in lines:
            if line.lstrip().startswith("#"):
                continue
            for h in HASH_RE.findall(line):
                found += 1
                batch.append((h, label, source))
            if len(batch) >= 5000:
                added += self.db.add_known_hashes(batch)
                batch = []
        if batch:
            added += self.db.add_known_hashes(batch)
        return found, added

    # ---------- echantillons
    def add_features(self, sha256, label, source, features):
        """Ajoute les caracteristiques d'un fichier comme echantillon etiquete."""
        self.db.upsert_sample(sha256, 1 if label in (1, "malware") else 0,
                              source, {k: float(features.get(k, 0.0)) for k in FEATURE_NAMES})

    def ingest_folder(self, job, folder, label, recursive=True, max_files=5000):
        """Ingere tous les fichiers d'un dossier avec l'etiquette donnee ; retourne le bilan."""
        folder = Path(folder).expanduser()
        if not folder.is_dir():
            raise FileNotFoundError(f"Dossier introuvable : {folder}")
        files = []
        for root, _dirs, names in os.walk(folder):
            for n in names:
                p = Path(root) / n
                if p.is_file() and not p.is_symlink():
                    files.append(p)
            if not recursive:
                break
        files = files[:max_files]
        job["total"] = len(files)
        added = skipped = errors = 0
        for i, p in enumerate(files, 1):
            job["progress"] = i
            job["message"] = p.name
            status = self.ingest_file(p, label, f"dossier:{folder.name}")
            if status == "added":
                added += 1
            elif status == "duplicate":
                skipped += 1
            else:
                errors += 1
        return {"files": len(files), "added": added, "duplicates": skipped, "errors": errors}

    def ingest_file(self, path, label, source):
        """Extrait et conserve les caracteristiques d'UN fichier (sans le garder ni l'executer).

        Retourne "added", "duplicate" ou "error". Pour un fichier Windows (PE), le vecteur
        EMBER est aussi conserve : c'est ce qui permet a vos propres donnees d'enrichir le
        modele EMBER en plus de BODMAS.
        """
        malware = label in (1, "malware")
        try:
            r = deep_analyze(path)        # sans base ni modele : pas de boucle de retour
        except (OSError, ValueError):
            return "error"
        if self.db.has_sample(r["sha256"]):
            return "duplicate"
        self.add_features(r["sha256"], label, source, r["features"])
        if malware:
            self.db.add_known_hashes([(r["sha256"], "echantillon", source)])
        if self.vectors is not None and r["file_type"] == "pe":
            try:
                vec = ember_v2.file_vector(path, settings.EMBER_MAX_FILE_BYTES)
            except Exception:             # PE trop malforme pour pefile : on garde le reste
                vec = None
            if vec is not None:
                self.vectors.add(r["sha256"], 1 if malware else 0, source, vec)
        return "added"

    def ingest_archives(self, job, folder, label, password="infected", max_files=20000):
        """Ingere des archives ZIP protegees par mot de passe (ex. depot theZoo).

        Chaque membre est extrait dans un dossier temporaire, analyse puis SUPPRIME
        aussitot ; il n'est jamais execute. Les archives chiffrees en AES necessitent
        le module optionnel `pyzipper` (pip install pyzipper). Mot de passe usuel des
        collections de malwares : "infected".
        """
        import tempfile
        import zipfile
        try:
            import pyzipper                    # lecture AES (facultatif)
            opener = pyzipper.AESZipFile
        except ImportError:
            opener = zipfile.ZipFile
        archives = sorted(Path(folder).expanduser().rglob("*.zip"))
        if not archives:
            raise FileNotFoundError(f"Aucune archive .zip trouvee dans {folder}")
        job["total"] = len(archives)
        stats = {"archives": len(archives), "added": 0, "duplicates": 0, "errors": 0, "encrypted_unreadable": 0}
        for i, archive in enumerate(archives, 1):
            job["progress"], job["message"] = i, archive.name
            try:
                with opener(archive) as z:
                    z.setpassword(password.encode())
                    for info in z.infolist()[:50]:
                        if info.is_dir() or info.file_size > settings.EMBER_MAX_FILE_BYTES:
                            continue
                        with tempfile.TemporaryDirectory(prefix="cubernoyau_zip_") as tmp:
                            target = Path(tmp) / Path(info.filename).name   # jamais de chemin de l'archive
                            with z.open(info) as src, open(target, "wb") as out:
                                shutil.copyfileobj(src, out)
                            status = self.ingest_file(target, label, f"archive:{archive.stem[:40]}")
                        stats["added" if status == "added" else "duplicates" if status == "duplicate" else "errors"] += 1
                        if stats["added"] >= max_files:
                            return stats
            except (RuntimeError, NotImplementedError, zipfile.BadZipFile, OSError):
                stats["encrypted_unreadable"] += 1
        return stats

    def import_features_csv(self, text):
        """Importe des echantillons depuis un CSV (sha256, label, caracteristiques)."""
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames or "sha256" not in reader.fieldnames \
                or "label" not in reader.fieldnames:
            raise TrainingError("Le CSV doit contenir les colonnes sha256 et label.")
        added = bad = 0
        for row in reader:
            sha = (row.get("sha256") or "").strip().lower()
            lab = (row.get("label") or "").strip().lower()
            if not re.fullmatch(r"[a-f0-9]{64}", sha) or lab not in ("0", "1", "malware", "benign"):
                bad += 1
                continue
            try:
                feats = {k: float(row.get(k) or 0.0) for k in FEATURE_NAMES}
            except ValueError:
                bad += 1
                continue
            self.db.upsert_sample(sha, 1 if lab in ("1", "malware") else 0, "csv", feats)
            added += 1
        return {"added": added, "rejected": bad}

    def export_csv(self):
        """Exporte les echantillons en CSV : partageable, sans aucun fichier."""
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["sha256", "label"] + FEATURE_NAMES)
        for sha, label, _src, feats in self.db.all_samples():
            w.writerow([sha, label] + [feats.get(k, 0.0) for k in FEATURE_NAMES])
        return out.getvalue()

    def feedback(self, sha256, features, label, vector=None):
        """Retour utilisateur : 'malware' ou 'benign' (remplace une etiquette existante).

        `vector` : vecteur EMBER du fichier si l'analyse vient d'etre faite (il est conserve
        en memoire un moment, car le fichier televerse est supprime apres l'analyse).
        """
        malware = label == "malware"
        self.add_features(sha256, 1 if malware else 0, "feedback", features)
        if vector is not None and self.vectors is not None:
            self.vectors.add(sha256, 1 if malware else 0, "feedback", vector)
        if malware:
            self.db.add_known_hashes([(sha256, "signale par un utilisateur", "feedback")])
        else:
            self.db.remove_known_hash(sha256)

    # ---------- entrainement
    def status(self):
        """Etat complet pour l'interface : donnees, modeles, seuils, taches."""
        counts = self.db.sample_counts()
        active = self.db.active_model()
        return {
            "samples": counts, "known_hashes": self.db.count_known_hashes(),
            "active_model": active, "models": self.db.list_models(),
            "auto_train": self.db.get_setting("auto_train", "1") == "1",
            "auto_train_min_new": settings.AUTO_TRAIN_MIN_NEW,
            "min_samples": settings.MIN_TRAIN_SAMPLES, "min_per_class": settings.MIN_PER_CLASS,
            "new_since_last_training": max(0, counts["total"] - self.db.last_model_samples()),
            "ready": counts["total"] >= settings.MIN_TRAIN_SAMPLES
                     and min(counts["malware"], counts["benign"]) >= settings.MIN_PER_CLASS,
            "classifier_active": self.classifier.available,
            "feature_count": len(FEATURE_NAMES), "jobs": list(self.jobs.values())[-10:],
        }

    def train(self, job=None, test_size=0.25, force_activate=False, seed=42):
        """Entraine un RandomForest (decoupage stratifie), evalue et enregistre ; active le modele s'il n'est pas moins bon."""
        rows = self.db.all_samples()
        y = np.array([r[1] for r in rows])
        mal, ben = int((y == 1).sum()), int((y == 0).sum())
        if len(rows) < settings.MIN_TRAIN_SAMPLES or min(mal, ben) < settings.MIN_PER_CLASS:
            raise TrainingError(
                f"Donnees insuffisantes : {mal} malveillants, {ben} sains "
                f"(minimum {settings.MIN_PER_CLASS} par classe, {settings.MIN_TRAIN_SAMPLES} au total).")
        X = np.array([[r[3].get(k, 0.0) for k in FEATURE_NAMES] for r in rows])
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=test_size,
                                              stratify=y, random_state=seed)
        model = RandomForestClassifier(
            n_estimators=300, class_weight="balanced_subsample",
            min_samples_leaf=2, n_jobs=-1, random_state=seed)
        model.fit(Xtr, ytr)
        pred = model.predict(Xte)
        proba = model.predict_proba(Xte)[:, list(model.classes_).index(1)]
        tn, fp, fn, tp = confusion_matrix(yte, pred, labels=[0, 1]).ravel()
        metrics = {
            "precision": round(float(precision_score(yte, pred, zero_division=0)), 4),
            "recall": round(float(recall_score(yte, pred, zero_division=0)), 4),
            "f1": round(float(f1_score(yte, pred, zero_division=0)), 4),
            "roc_auc": round(float(roc_auc_score(yte, proba)), 4) if len(set(yte)) == 2 else None,
            "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            "n_train": int(len(ytr)), "n_test": int(len(yte)),
            "malware": mal, "benign": ben,
            "top_features": [
                [FEATURE_NAMES[i], round(float(model.feature_importances_[i]), 4)]
                for i in np.argsort(model.feature_importances_)[::-1][:8]],
        }
        # le modele final est reentraine sur toutes les donnees (la validation reste celle du test)
        final = RandomForestClassifier(
            n_estimators=300, class_weight="balanced_subsample",
            min_samples_leaf=2, n_jobs=-1, random_state=seed).fit(X, y)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        path = self.models_dir / f"model_{int(time.time() * 1000)}.joblib"
        joblib.dump({"model": final, "feature_names": FEATURE_NAMES}, path)

        current = self.db.active_model()
        better = (current is None or force_activate
                  or metrics["f1"] >= (current["metrics"].get("f1") or 0) - 0.02)
        model_id = self.db.add_model(path, len(rows), metrics, active=better)
        if better:
            self.classifier.reload()
        return {"model_id": model_id, "activated": better, "metrics": metrics}

    def activate(self, model_id):
        """Rend un modele precedent actif."""
        if not self.db.set_active_model(model_id):
            raise TrainingError("Modele introuvable.")
        self.classifier.reload()

    # ---------- entrainement automatique
    def maybe_auto_train(self):
        """Appele a chaque cycle : relance l'entrainement quand assez de nouvelles donnees."""
        if self.db.get_setting("auto_train", "1") != "1" or self.job_running("train"):
            return None
        counts = self.db.sample_counts()
        if counts["total"] - self.db.last_model_samples() < settings.AUTO_TRAIN_MIN_NEW:
            return None
        if counts["total"] < settings.MIN_TRAIN_SAMPLES or \
                min(counts["malware"], counts["benign"]) < settings.MIN_PER_CLASS:
            return None
        return self.start_job("train", lambda job: self.train(job))

    def maybe_auto_train_ember(self):
        """Reentraine le modele EMBER quand assez de NOUVEAUX vecteurs se sont accumules.

        Appele a chaque cycle de surveillance, comme `maybe_auto_train`. Seuil : cinq fois
        AUTO_TRAIN_MIN_NEW vecteurs, car l'entrainement EMBER est plus long (quelques minutes).
        Desactivable : reglage "auto_train_ember" = 0.
        """
        if self.vectors is None or self.job_running("ember"):
            return None
        if self.db.get_setting("auto_train_ember", "1") != "1":
            return None
        total = self.vectors.counts()["total"]
        last = int(self.db.get_setting("ember.last_vectors", "0"))
        if total - last < settings.AUTO_TRAIN_MIN_NEW * 5:
            return None
        try:
            import lightgbm  # noqa: F401
        except ImportError:
            return None
        from cubernoyau.training import ember_model

        def run(job):
            """Corps de la tache : entraine EMBER et memorise le nombre de vecteurs utilises."""
            meta = ember_model.train_from_sources(self.db, profile="rapide", progress=lambda i, n, m: job.update(
                progress=i, total=n, message=m))
            self.db.set_setting("ember.last_vectors", str(total))
            self.classifier_ember_reload()
            return {"model": meta["name"], "metrics": meta["metrics"]}
        return self.start_job("ember", run)

    def classifier_ember_reload(self):
        """Point d'accroche : MonitorService remplace cette methode pour recharger le modele actif."""
