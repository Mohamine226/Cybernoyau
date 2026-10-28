"""BODMAS -> listes d'empreintes (base de malwares connus + liste de fichiers sains).

    python tools/import_bodmas.py

1. genere data/threat_intel/hashes/{malware,benign}/bodmas.*.gz a partir des metadonnees ;
2. synchronise ces listes dans la base (un fichier deja importe n'est pas re-importe).
Apres cela, tout fichier dont l'empreinte est dans BODMAS est reconnu instantanement,
meme hors ligne. (L'ENTRAINEMENT du modele se lance avec tools/train_ember.py.)
"""
import _common
from cubernoyau.intel import loaders
from cubernoyau.intel.store import IntelStore

if __name__ == "__main__":
    made = loaders.bodmas_to_intel_files()
    print("Listes generees :", made)
    store = IntelStore(_common.open_db())
    for row in loaders.sync_intel_folders(store, force=True):
        print(f"  {row['file']}: {row['rows']} lignes, {row['added']} ajoutees")
    print(store.counts())
