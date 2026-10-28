"""Modele EMBER en service : charge le modele actif et note les fichiers Windows (PE).

Le modele (LightGBM) est enregistre au format TEXTE (data/models/ember/model_*.txt)
accompagne d'un fichier de metadonnees (model_*.json : metriques, seuils). Contrairement
a un fichier pickle/joblib, un modele texte ne peut pas executer de code a son chargement :
on peut donc echanger des modeles entre postes sans risque.

Le fichier `active.json` indique quel modele est utilise. Si LightGBM n'est pas installe
ou si aucun modele n'est entraine, le classifieur reste inactif et dit pourquoi
(`error`), sans jamais inventer de probabilite.
"""

import json
import threading
from pathlib import Path

from cubernoyau.config import settings
from cubernoyau.features import ember_v2


def _dir(directory=None):
    """Dossier des modeles EMBER (parametre ou reglage)."""
    return Path(directory or settings.EMBER_DIR)


def list_models(directory=None):
    """Metadonnees de tous les modeles EMBER, du plus recent au plus ancien."""
    out = []
    for meta in sorted(_dir(directory).glob("model_*.json"), reverse=True):
        try:
            item = json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        item["file"] = meta.with_suffix(".txt").name
        out.append(item)
    active = active_name(directory)
    for item in out:
        item["active"] = item["file"] == active
    return out


def active_name(directory=None):
    """Nom du fichier du modele actif (le plus recent si aucun choix explicite)."""
    d = _dir(directory)
    pointer = d / "active.json"
    if pointer.is_file():
        try:
            name = json.loads(pointer.read_text(encoding="utf-8")).get("model")
            if name and (d / name).is_file():
                return name
        except (OSError, ValueError):
            pass
    models = sorted(d.glob("model_*.txt"), reverse=True)
    return models[0].name if models else None


def set_active(name, directory=None):
    """Choisit le modele actif (retour arriere possible vers un modele precedent)."""
    d = _dir(directory)
    if not (d / name).is_file():
        raise FileNotFoundError(f"Modele introuvable : {name}")
    (d / "active.json").write_text(json.dumps({"model": name}), encoding="utf-8")


class EmberClassifier:
    """Note un fichier PE : probabilite d'etre malveillant + niveau de gravite."""

    def __init__(self, directory=None):
        self.directory = _dir(directory)
        self._lock = threading.Lock()
        self._booster = None
        self._meta = {}
        self.error = None
        self.reload()

    def reload(self):
        """(Re)charge le modele actif ; a appeler apres un entrainement ou un changement."""
        booster, meta, error = None, {}, None
        name = active_name(self.directory)
        if name is None:
            error = "Aucun modele EMBER entraine (voir la page Donnees et entrainement)."
        else:
            try:
                import lightgbm as lgb  # import tardif : la dependance reste optionnelle
                booster = lgb.Booster(model_file=str(self.directory / name))
                meta = json.loads((self.directory / name).with_suffix(".json").read_text(encoding="utf-8"))
                meta["file"] = name
            except ImportError:
                error = "LightGBM n'est pas installe (pip install lightgbm)."
            except Exception as exc:  # modele corrompu ou incompatible
                error = f"Modele illisible : {exc}"
        with self._lock:
            self._booster, self._meta, self.error = booster, meta, error

    @property
    def available(self):
        """True si un modele est charge."""
        return self._booster is not None

    def info(self):
        """Resume du modele actif (pour l'interface et les rapports)."""
        meta = dict(self._meta)
        return {"model": meta.get("file"), "trained_at": meta.get("created_at"),
                "profile": meta.get("profile"), "auc": (meta.get("metrics") or {}).get("roc_auc"),
                "thresholds": meta.get("thresholds"), "n_samples": meta.get("n_total")}

    def predict_vector(self, vector):
        """Probabilite (0..1) pour un vecteur EMBER de 2381 valeurs."""
        with self._lock:
            booster = self._booster
        if booster is None:
            return 0.0
        return float(booster.predict([vector])[0])

    def severity(self, probability):
        """Gravite d'apres les SEUILS MESURES a l'entrainement (pas des seuils arbitraires).

        high   : score au-dessus duquel seuls 0,1 % des fichiers sains de validation passent ;
        medium : idem 1 % ; low : idem 5 %. Retourne None sous le dernier seuil.
        """
        t = self._meta.get("thresholds") or {}
        for level in ("high", "medium", "low"):
            if level in t and probability >= t[level]:
                return level
        return None

    def score_file(self, path):
        """(vecteur, probabilite) d'un fichier PE, ou None s'il n'est pas applicable."""
        if not self.available:
            return None
        vec = ember_v2.file_vector(path, settings.EMBER_MAX_FILE_BYTES)
        if vec is None:
            return None
        return vec, self.predict_vector(vec)
