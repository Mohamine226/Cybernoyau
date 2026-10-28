"""Ingere un dossier de fichiers etiquetes (sans les executer ni les conserver).

    python tools/ingest_folder.py --label malware  data/datasets/custom/malware
    python tools/ingest_folder.py --label benign   "C:\\Program Files\\MonLogiciel"

Conserve : caracteristiques (modele Cubernoyau) + vecteur EMBER des fichiers Windows + empreinte.
Travaillez pour les malwares dans une MACHINE VIRTUELLE ISOLEE.
"""
import argparse

import _common
from cubernoyau.models.file_classifier import FileClassifier
from cubernoyau.training.ember_model import VectorStore
from cubernoyau.training.service import TrainingService

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder")
    ap.add_argument("--label", choices=["malware", "benign"], required=True)
    ap.add_argument("--max-files", type=int, default=200000)
    a = ap.parse_args()
    db = _common.open_db()
    service = TrainingService(db, FileClassifier(db), vectors=VectorStore(db))
    print(service.ingest_folder(_common.ConsoleJob(), a.folder, a.label, True, a.max_files))
