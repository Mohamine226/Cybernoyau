"""Telecharge un SOUS-ENSEMBLE d'echantillons SOREL-20M (public, desarmes) pour l'entrainement.

    python tools/download_sorel.py data/datasets/sorel20m/meta.db --count 500 --label malware

Les fichiers sont compresses (zlib) sur S3 : ils sont decompresses dans
data/datasets/sorel20m/binaries/ (nom = SHA-256 d'origine). Ils sont "desarmes" (champs Machine et
Subsystem a 0) et ne s'executent pas. Ingestion ensuite : page "Donnees" ou
`python tools/ingest_folder.py --label malware data/datasets/sorel20m/binaries`.
ATTENTION : fichiers dangereux malgre tout -> machine virtuelle ; conditions d'utilisation SOREL a respecter.
Non teste contre le serveur reel depuis l'environnement de developpement (reseau ferme) : si l'adresse
du bucket change, ajustez BUCKET ci-dessous.
"""
import argparse
import sqlite3
import urllib.error
import urllib.request
import zlib
from pathlib import Path

import _common
from cubernoyau.config import settings

BUCKET = "http://sorel-20m.s3.amazonaws.com/09-DEC-2020/binaries/"


def fetch(sha, timeout=60):
    """Telecharge et decompresse un echantillon ; None s'il est introuvable."""
    try:
        with urllib.request.urlopen(BUCKET + sha, timeout=timeout) as response:   # noqa: S310
            return zlib.decompress(response.read())
    except (urllib.error.URLError, zlib.error, TimeoutError):
        return None


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("meta_db")
    ap.add_argument("--count", type=int, default=200)
    ap.add_argument("--label", choices=["malware", "benign"], default="malware")
    ap.add_argument("--min-positives", type=int, default=5)
    a = ap.parse_args()
    out = settings.SOREL_DIR / "binaries"
    out.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(f"file:{a.meta_db}?mode=ro", uri=True)
    flag = 1 if a.label == "malware" else 0
    rows = conn.execute("select sha256 from meta where is_malware = ? and rl_ls_const_positives >= ? "
                        "order by random() limit ?", (flag, a.min_positives if flag else 0, a.count)).fetchall()
    ok = 0
    for i, (sha,) in enumerate(rows, 1):
        target = Path(out) / sha
        if target.exists() or (data := fetch(sha)) is None:
            ok += target.exists()
            continue
        target.write_bytes(data)
        ok += 1
        if i % 25 == 0:
            print(f"  {i}/{len(rows)}")
    print(f"{ok}/{len(rows)} echantillons disponibles dans {out}")
