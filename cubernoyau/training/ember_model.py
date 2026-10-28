"""Entrainement du modele EMBER (LightGBM) sur BODMAS et sur vos propres fichiers.

Principe (comme dans les articles EMBER / SOREL-20M) : le decoupage est
CHRONOLOGIQUE et non aleatoire. Les malwares evoluent ; un modele doit etre juge
sur des fichiers PLUS RECENTS que ceux qui l'ont entraine, sinon on surestime sa
qualite. Ici :
    entrainement  = les 75 % de fichiers les plus anciens
    validation    = les 10 % suivants  (arret anticipe + calcul des seuils d'alerte)
    test          = les 15 % les plus recents (jamais vus : metriques reportees)

Les SEUILS de gravite sont calcules sur la validation : "high" = score au-dessus
duquel seuls 0,1 % des fichiers sains passent, "medium" = 1 %, "low" = 5 %. Les
metriques de test (taux de detection a ces seuils) disent honnetement ce que le
modele vaut sur des fichiers recents. Attention : sur VOTRE ordinateur la
proportion de fichiers sains est bien plus grande que dans BODMAS (43 % de
malwares) : un faux positif y est relativement plus frequent. D'ou les seuils prudents.
"""

import json
import os
import time
import warnings
import zlib
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from cubernoyau.config import settings
from cubernoyau.features import ember_v2
from cubernoyau.models import ember_classifier

# Profils d'entrainement ----------------------------------------------------------
# "standard" reprend les hyperparametres de reference du depot SOREL-20M
# (third_party/SOREL-20M/lightgbm_config.json). "rapide" sacrifie un peu de
# precision pour tenir en quelques minutes sur un ordinateur modeste.
PROFILES = {
    "standard": {
        "params": {"objective": "binary", "boosting": "gbdt", "learning_rate": 0.1, "num_leaves": 64,
                   "min_data_in_leaf": 100, "min_sum_hessian_in_leaf": 0.001, "bagging_fraction": 0.9,
                   "bagging_freq": 1, "feature_fraction": 0.9, "feature_fraction_bynode": 0.9,
                   "lambda_l2": 1.0, "is_unbalance": True, "metric": ["auc", "binary_logloss"]},
        "rounds": 500, "early_stopping": 10,
    },
    "rapide": {
        "params": {"objective": "binary", "boosting": "gbdt", "learning_rate": 0.15, "num_leaves": 64,
                   "min_data_in_leaf": 100, "bagging_fraction": 0.5, "bagging_freq": 1,
                   "feature_fraction": 0.5, "lambda_l2": 1.0, "max_bin": 63,
                   "metric": ["auc", "binary_logloss"]},
        "rounds": 250, "early_stopping": 15,
    },
}
FPR_TARGETS = {"high": 0.001, "medium": 0.01, "low": 0.05}   # taux de faux positifs vises


class VectorStore:
    """Vecteurs EMBER de VOS fichiers (ingestion de dossiers, retours utilisateurs).

    Un vecteur = 2381 float32 compresses (~5 Ko). On ne conserve jamais le fichier.
    Ces vecteurs s'ajoutent a BODMAS lors de l'entrainement : c'est ainsi que le
    modele s'ameliore avec vos donnees (theZoo, vos programmes sains, retours).
    """

    def __init__(self, db):
        self.db = db
        with db._lock, db._conn:
            db._conn.execute(
                "CREATE TABLE IF NOT EXISTS ember_vectors (sha256 TEXT PRIMARY KEY, label INTEGER NOT NULL,"
                " source TEXT NOT NULL, added_at REAL NOT NULL, vec BLOB NOT NULL)")

    def add(self, sha256, label, source, vector):
        """Conserve (compresse) le vecteur EMBER d'un fichier avec son etiquette."""
        blob = zlib.compress(np.asarray(vector, dtype=np.float32).tobytes(), 3)
        with self.db._lock, self.db._conn:
            self.db._conn.execute("INSERT OR REPLACE INTO ember_vectors VALUES (?, ?, ?, ?, ?)",
                                  (sha256.lower(), int(label), source[:80], time.time(), blob))

    def has(self, sha256):
        """True si l'empreinte a deja un vecteur."""
        with self.db._lock:
            return self.db._conn.execute("SELECT 1 FROM ember_vectors WHERE sha256 = ?",
                                         (sha256.lower(),)).fetchone() is not None

    def counts(self):
        """Nombre de vecteurs par classe."""
        with self.db._lock:
            rows = self.db._conn.execute("SELECT label, COUNT(*) FROM ember_vectors GROUP BY label").fetchall()
        c = {int(r[0]): r[1] for r in rows}
        return {"malware": c.get(1, 0), "benign": c.get(0, 0), "total": sum(c.values())}

    def load_all(self):
        """(X, y, horodatages) de tous les vecteurs ; tableaux vides s'il n'y en a pas."""
        with self.db._lock:
            rows = self.db._conn.execute("SELECT label, added_at, vec FROM ember_vectors").fetchall()
        if not rows:
            return np.zeros((0, ember_v2.DIM), np.float32), np.zeros(0, np.int8), np.zeros(0)
        X = np.stack([np.frombuffer(zlib.decompress(r[2]), dtype=np.float32) for r in rows])
        return X, np.array([r[0] for r in rows], dtype=np.int8), np.array([r[1] for r in rows])


def chronological_split(ts, train=0.75, valid=0.10):
    """Indices (entrainement, validation, test) en suivant l'ordre du temps."""
    order = np.argsort(ts, kind="stable")
    n = len(order)
    a, b = int(n * train), int(n * (train + valid))
    return order[:a], order[a:b], order[b:]


def _thresholds(valid_scores, valid_y):
    """Seuils de gravite : score depasse par seulement x % des fichiers sains de validation."""
    benign = valid_scores[valid_y == 0]
    out = {name: float(np.quantile(benign, 1 - fpr)) for name, fpr in FPR_TARGETS.items()}
    # Garantit high >= medium >= low meme sur de petits jeux.
    out["medium"] = min(out["medium"], out["high"])
    out["low"] = min(out["low"], out["medium"])
    return out


def train_ember(X, y, ts, profile="rapide", progress=None, out_dir=None, sources=None, threads=None):
    """Entraine, evalue et enregistre un modele EMBER. Retourne ses metadonnees.

    X : tableau (n, 2381) float32 ; y : 0 sain / 1 malveillant ; ts : horodatages (secondes).
    progress(i, total, message) : rappel optionnel pour l'interface.
    """
    import lightgbm as lgb                       # dependance optionnelle (voir requirements.txt)
    from sklearn.metrics import average_precision_score, roc_auc_score

    if profile not in PROFILES:
        raise ValueError(f"Profil inconnu : {profile} ({', '.join(PROFILES)})")
    spec = PROFILES[profile]
    if X.shape[1] != ember_v2.DIM:
        raise ValueError(f"Il faut {ember_v2.DIM} caracteristiques par fichier, pas {X.shape[1]}.")
    if min((y == 0).sum(), (y == 1).sum()) < 50:
        raise ValueError("Il faut au moins 50 fichiers sains et 50 malveillants pour entrainer ce modele.")
    note = progress or (lambda i, n, msg: None)

    note(0, spec["rounds"], "Decoupage chronologique...")
    i_tr, i_va, i_te = chronological_split(ts)
    params = dict(spec["params"], verbose=-1, num_threads=threads or os.cpu_count() or 1, seed=0)
    # "min_data_in_leaf" fixe combien de fichiers au minimum doit contenir une feuille d'arbre.
    # La valeur de reference (100) convient a 100 000 fichiers mais empeche tout apprentissage
    # sur un petit jeu : on la reduit proportionnellement a la taille de l'entrainement.
    params["min_data_in_leaf"] = max(3, min(params.get("min_data_in_leaf", 20), len(i_tr) // 50))

    # Le jeu d'entrainement est converti en classes de valeurs (histogrammes) : c'est
    # ce qui rend LightGBM rapide. La copie brute est liberee des que possible.
    note(0, spec["rounds"], "Preparation des donnees d'entrainement...")
    with warnings.catch_warnings():              # LightGBM signale (a tort) une surcharge de parametres
        warnings.simplefilter("ignore")
        # Les parametres qui touchent au decoupage des donnees doivent etre connus du Dataset
        # des sa creation (sinon LightGBM refuse de changer min_data_in_leaf plus tard).
        ds_params = {"max_bin": params.get("max_bin", 255), "verbose": -1,
                     "min_data_in_leaf": params["min_data_in_leaf"], "feature_pre_filter": False}
        dtrain = lgb.Dataset(X[i_tr], y[i_tr], params=ds_params)
        dtrain.construct()
        dvalid = lgb.Dataset(X[i_va], y[i_va], reference=dtrain, params=ds_params)
        dvalid.construct()

    def on_iteration(env):                       # remonte l'avancement a l'interface
        """Rappel LightGBM : remonte l'avancement a l'interface."""
        note(env.iteration + 1, spec["rounds"], f"Iteration {env.iteration + 1}/{spec['rounds']}")

    params["feature_pre_filter"] = False
    booster = lgb.train(params, dtrain, num_boost_round=spec["rounds"], valid_sets=[dvalid],
                        valid_names=["validation"],
                        callbacks=[lgb.early_stopping(spec["early_stopping"], verbose=False), on_iteration])
    best = booster.best_iteration or booster.current_iteration()

    note(best, spec["rounds"], "Evaluation sur les fichiers les plus recents...")
    p_va = booster.predict(X[i_va], num_iteration=best)
    thresholds = _thresholds(p_va, y[i_va])
    p_te, y_te = booster.predict(X[i_te], num_iteration=best), y[i_te]
    metrics = {"roc_auc": float(roc_auc_score(y_te, p_te)),
               "pr_auc": float(average_precision_score(y_te, p_te)),
               "accuracy_at_0.5": float(((p_te >= 0.5) == (y_te == 1)).mean())}
    for name, thr in thresholds.items():       # detection reelle aux seuils choisis sur la validation
        metrics[f"tpr_{name}"] = float((p_te[y_te == 1] >= thr).mean())
        metrics[f"fpr_{name}"] = float((p_te[y_te == 0] >= thr).mean())

    # --- enregistrement : modele texte + metadonnees JSON
    d = Path(out_dir or settings.EMBER_DIR)
    d.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    name = f"model_{stamp}"
    booster.save_model(str(d / f"{name}.txt"), num_iteration=best)
    meta = {
        "name": name, "created_at": datetime.now(timezone.utc).isoformat(), "profile": profile,
        "feature_version": "ember-v2-2381", "num_iterations": int(best),
        "n_total": int(len(y)), "n_train": int(len(i_tr)), "n_valid": int(len(i_va)), "n_test": int(len(i_te)),
        "time_range": {"train_end": float(ts[i_tr].max()), "test_start": float(ts[i_te].min()),
                       "test_end": float(ts[i_te].max())},
        "malware_ratio": float(y.mean()), "thresholds": thresholds, "metrics": metrics,
        "sources": sources or [], "hyperparameters": {k: v for k, v in params.items() if k != "verbose"},
    }
    (d / f"{name}.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    ember_classifier.set_active(f"{name}.txt", d)   # le nouveau modele devient le modele actif
    note(best, spec["rounds"], "Termine.")
    return meta


def train_from_sources(db=None, profile="rapide", use_bodmas=True, progress=None, out_dir=None):
    """Assemble BODMAS (si present) + vos vecteurs, puis entraine."""
    from cubernoyau.training import datasets
    parts_X, parts_y, parts_t, sources = [], [], [], []
    if use_bodmas and (settings.BODMAS_DIR / "bodmas.npz").is_file():
        X, y, ts, _ = datasets.load_bodmas()
        parts_X.append(X), parts_y.append(y), parts_t.append(ts), sources.append(f"bodmas:{len(y)}")
    if db is not None:
        Xu, yu, tu = VectorStore(db).load_all()
        if len(yu):
            parts_X.append(Xu), parts_y.append(yu), parts_t.append(tu), sources.append(f"vos fichiers:{len(yu)}")
    if not parts_X:
        raise ValueError("Aucune donnee : placez BODMAS dans data/datasets/bodmas/ ou ingerez vos fichiers.")
    X = np.concatenate(parts_X) if len(parts_X) > 1 else parts_X[0]
    y, ts = np.concatenate(parts_y), np.concatenate(parts_t)
    del parts_X                                   # libere la memoire avant l'entrainement
    return train_ember(X, y, ts, profile=profile, progress=progress, out_dir=out_dir, sources=sources)
