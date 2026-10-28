"""Outils communs aux scripts en ligne de commande (a importer en premier).

Les scripts se lancent depuis la racine du projet : `python tools/train_ember.py ...`
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))                    # permet `import cubernoyau` sans installation

from cubernoyau.config import settings           # noqa: E402
from cubernoyau.storage.database import Database  # noqa: E402


def open_db():
    """Ouvre la base du projet (data/cubernoyau.db, ou CUBERNOYAU_DB)."""
    settings.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return Database(settings.DB_PATH)


class ConsoleJob(dict):
    """Imite la 'tache' de l'API : les fonctions d'entrainement y ecrivent leur avancement."""

    def __init__(self):
        super().__init__(progress=0, total=0, message="")
        self._last = -1

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if key == "progress" and self.get("total") and value != self._last and (value % 25 == 0 or value == self["total"]):
            self._last = value
            print(f"  {value}/{self['total']} {self.get('message', '')}", flush=True)
