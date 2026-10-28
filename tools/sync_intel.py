"""Importe les listes de data/threat_intel/ (empreintes, liens) dans la base.

    python tools/sync_intel.py [--force]
"""
import argparse

import _common
from cubernoyau.intel import loaders
from cubernoyau.intel.store import IntelStore

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--force", action="store_true", help="re-importer meme les fichiers inchanges")
    store = IntelStore(_common.open_db())
    for row in loaders.sync_intel_folders(store, force=ap.parse_args().force):
        print(f"{row['file']}: {row['rows']} lignes, {row['added']} ajoutees")
    print(store.counts())
