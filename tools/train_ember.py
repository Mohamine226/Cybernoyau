"""Entraine le modele EMBER (LightGBM) sur BODMAS + vos vecteurs, puis l'active.

    python tools/train_ember.py                      # profil rapide (quelques minutes)
    python tools/train_ember.py --profile standard   # hyperparametres de reference SOREL-20M
    python tools/train_ember.py --no-bodmas          # seulement vos propres fichiers

Les metriques sont mesurees sur les fichiers les PLUS RECENTS (decoupage chronologique).
Besoin : lightgbm (pip install lightgbm), ~4 Go de memoire pour BODMAS complet.
"""
import argparse
import json

import _common
from cubernoyau.training import ember_model

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", choices=list(ember_model.PROFILES), default="rapide")
    ap.add_argument("--no-bodmas", action="store_true")
    args = ap.parse_args()
    job = _common.ConsoleJob()
    meta = ember_model.train_from_sources(
        _common.open_db(), profile=args.profile, use_bodmas=not args.no_bodmas,
        progress=lambda i, n, m: job.update(progress=i, total=n, message=m))
    print(json.dumps({k: meta[k] for k in ("name", "num_iterations", "n_total", "thresholds", "metrics")}, indent=2))
