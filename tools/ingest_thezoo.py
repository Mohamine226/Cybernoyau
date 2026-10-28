"""Ingere un clone de theZoo (archives .zip protegees par mot de passe), sans rien executer.

    git clone https://github.com/ytisf/theZoo.git data/datasets/thezoo/repo
    python tools/ingest_thezoo.py

Chaque archive est ouverte avec le mot de passe "infected", ses fichiers sont analyses un par un
dans un dossier temporaire puis SUPPRIMES. Seuls des nombres sont conserves (caracteristiques,
empreinte, vecteur EMBER). Archives chiffrees en AES : pip install pyzipper.
Votre antivirus peut bloquer le clone : excluez le dossier ou travaillez en machine virtuelle.
"""
import argparse

import _common
from cubernoyau.config import settings
from cubernoyau.models.file_classifier import FileClassifier
from cubernoyau.training.ember_model import VectorStore
from cubernoyau.training.service import TrainingService

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", nargs="?", default=str(settings.THEZOO_DIR / "repo"))
    ap.add_argument("--password", default="infected")
    a = ap.parse_args()
    db = _common.open_db()
    service = TrainingService(db, FileClassifier(db), vectors=VectorStore(db))
    print(service.ingest_archives(_common.ConsoleJob(), a.folder, "malware", a.password))
