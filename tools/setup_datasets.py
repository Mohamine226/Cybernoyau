"""Range les jeux de donnees fournis (zip ou dossier) a leur place dans data/datasets/.

    python tools/setup_datasets.py --bodmas "dataset de bodmas.zip" --sorel SOREL-20M.zip

Cherche les fichiers attendus n'importe ou dans l'archive/le dossier et les copie :
    BODMAS  -> data/datasets/bodmas/   (bodmas.npz, bodmas_metadata.csv, bodmas_malware_category.csv)
    SOREL   -> data/datasets/sorel20m/ (shas_missing_ember_features.json, pe_full_metadata_example/, meta.db)
Le CODE de SOREL est deja integre dans third_party/SOREL-20M/ (inutile de le copier).
"""
import argparse
import shutil
import tempfile
import zipfile
from pathlib import Path

import _common  # noqa: F401
from cubernoyau.config import settings

WANTED = {
    "bodmas": (settings.BODMAS_DIR, ["bodmas.npz", "bodmas_metadata.csv", "bodmas_malware_category.csv"]),
    "sorel": (settings.SOREL_DIR, ["shas_missing_ember_features.json", "pe_full_metadata_example", "meta.db"]),
}


def place(source, key):
    """Copie les elements attendus trouves sous `source` (dossier ou .zip). Retourne la liste copiee."""
    dest, names = WANTED[key]
    dest.mkdir(parents=True, exist_ok=True)
    source = Path(source)
    tmp = None
    if source.suffix.lower() == ".zip":
        tmp = tempfile.mkdtemp(prefix="cubernoyau_setup_")
        with zipfile.ZipFile(source) as z:
            z.extractall(tmp)
        source = Path(tmp)
    copied = []
    try:
        for name in names:
            found = next(iter(source.rglob(name)), None)
            if found is None:
                continue
            target = dest / name
            if found.is_dir():
                shutil.copytree(found, target, dirs_exist_ok=True)
            else:
                shutil.copy2(found, target)
            copied.append(str(target))
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    return copied


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bodmas", help="zip ou dossier contenant les fichiers BODMAS")
    ap.add_argument("--sorel", help="zip ou dossier du depot / des donnees SOREL-20M")
    args = ap.parse_args()
    if not (args.bodmas or args.sorel):
        ap.error("Indiquez --bodmas et/ou --sorel")
    for key in ("bodmas", "sorel"):
        src = getattr(args, key)
        if src:
            done = place(src, key)
            print(f"{key}: {len(done)} element(s) range(s)", *done, sep="\n  ")
