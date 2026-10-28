"""SOREL-20M meta.db -> empreintes (liste de malwares connus et/ou de fichiers sains).

    python tools/import_sorel_meta.py data/datasets/sorel20m/meta.db --limit 2000000 --min-positives 5

meta.db (3,5 Go) est telechargeable : http://sorel-20m.s3.amazonaws.com/09-DEC-2020/processed-data/meta.db
Colonnes utilisees (schema du depot SOREL) : sha256, is_malware, rl_ls_const_positives.
Attention : l'empreinte SOREL est celle du fichier ORIGINAL ; les echantillons SOREL sont "desarmes"
(en-tete modifie), leur empreinte differe donc de celle du fichier distribue.
"""
import argparse
import sqlite3

import _common
from cubernoyau.intel.store import IntelStore

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("meta_db")
    ap.add_argument("--limit", type=int, default=2_000_000, help="nombre maximal d'empreintes par classe")
    ap.add_argument("--min-positives", type=int, default=5,
                    help="detections antivirus minimales pour un malware (5 = seuil EMBER2024)")
    ap.add_argument("--benign", action="store_true", help="importer aussi des empreintes de fichiers sains")
    a = ap.parse_args()
    store = IntelStore(_common.open_db())
    conn = sqlite3.connect(f"file:{a.meta_db}?mode=ro", uri=True)       # lecture seule
    cur = conn.execute("select sha256 from meta where is_malware = 1 and rl_ls_const_positives >= ? limit ?",
                       (a.min_positives, a.limit))
    print("malwares ajoutes :", store.add_malware_hashes((r[0], "SOREL-20M", "sorel20m") for r in cur))
    if a.benign:
        cur = conn.execute("select sha256 from meta where is_malware = 0 limit ?", (a.limit,))
        print("sains ajoutes :", store.add_benign_hashes((r[0], "sorel20m") for r in cur))
    print(store.counts())
