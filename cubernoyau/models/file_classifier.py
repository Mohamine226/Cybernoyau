"""Classifieur de fichiers (sain / malveillant) entraine sur des donnees reelles.

Utilise le modele actif enregistre en base. Sans modele entraine, il reste
inactif : aucune probabilite n'est inventee.
"""

import threading
from pathlib import Path

import joblib


class FileClassifier:
    """Modele Cubernoyau (RandomForest) en service : probabilite de malveillance d'un fichier de tout type."""
    def __init__(self, db):
        self.db = db
        self._lock = threading.Lock()
        self._bundle = None
        self._meta = {}
        self.reload()

    def reload(self):
        """(Re)charge le modele actif depuis la base."""
        row = self.db.active_model()
        bundle, meta = None, {}
        if row and Path(row["path"]).is_file():
            try:
                bundle = joblib.load(row["path"])
                meta = {"model_id": row["id"], "n_samples": row["n_samples"],
                        "f1": row["metrics"].get("f1"),
                        "trained_at": row["created_at"]}
            except Exception:  # fichier de modele illisible
                bundle = None
        with self._lock:
            self._bundle, self._meta = bundle, meta

    @property
    def available(self):
        """True si un modele est charge."""
        return self._bundle is not None

    def info(self):
        """Metadonnees du modele actif."""
        return dict(self._meta)

    def predict(self, features):
        """Probabilite (0..1) d'etre malveillant pour un dictionnaire de caracteristiques."""
        with self._lock:
            bundle = self._bundle
        if bundle is None:
            return 0.0
        names = bundle["feature_names"]
        row = [[float(features.get(n, 0.0)) for n in names]]
        model = bundle["model"]
        classes = list(model.classes_)
        if 1 not in classes:
            return 0.0
        return float(model.predict_proba(row)[0][classes.index(1)])
