"""Registre des jeux de donnees : ou ils sont, s'ils sont presents, ce qu'on peut en faire.

Chaque jeu vit dans son dossier (data/datasets/<nom>/, avec un README.md qui
explique ou placer les fichiers). Ce module ne charge rien en memoire : il
inspecte les dossiers et renvoie un etat lisible par l'interface et les outils.

Pour ajouter un nouveau jeu : creer son dossier, ajouter une entree dans
`discover()` (nom, fichiers attendus, actions possibles) et, si besoin, une
fonction de chargement comme `load_bodmas()`.
"""

import csv
from datetime import datetime
from pathlib import Path

import numpy as np

from cubernoyau.config import settings


def _count_lines(path):
    """Nombre de lignes d'un gros fichier texte, lu par blocs (rapide, memoire constante)."""
    n = 0
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            n += block.count(b"\n")
    return n


def _folder_files(path, limit=100000):
    """(nombre de fichiers, taille totale) d'un dossier, README exclus."""
    count = size = 0
    if Path(path).is_dir():
        for p in Path(path).rglob("*"):
            if p.is_file() and p.name.lower() != "readme.md" and p.name != ".gitkeep":
                count += 1
                size += p.stat().st_size
                if count >= limit:
                    break
    return count, size


def discover():
    """Etat de tous les jeux connus : liste de dictionnaires pour l'interface."""
    out = []

    # --- BODMAS : vecteurs EMBER v2 + metadonnees (aucun fichier binaire)
    b = settings.BODMAS_DIR
    npz, meta = b / "bodmas.npz", b / "bodmas_metadata.csv"
    present = npz.is_file() and meta.is_file()
    out.append({
        "name": "bodmas", "title": "BODMAS", "path": str(b), "present": present,
        "description": "134 435 fichiers Windows (57 293 malveillants, 77 142 sains) sous forme de "
                       "2381 caracteristiques EMBER v2, avec date et famille. Sert a entrainer le modele EMBER.",
        "rows": (_count_lines(meta) - 1) if meta.is_file() else 0,
        "size_bytes": npz.stat().st_size if npz.is_file() else 0,
        "missing": [f.name for f in (npz, meta) if not f.is_file()],
        "actions": [{"id": "import_intel", "label": "Importer les empreintes"},
                    {"id": "train_ember", "label": "Entrainer le modele EMBER"}] if present else [],
    })

    # --- SOREL-20M : code present dans third_party ; donnees a telecharger
    s = settings.SOREL_DIR
    n_bin, size_bin = _folder_files(s / "binaries")
    out.append({
        "name": "sorel20m", "title": "SOREL-20M", "path": str(s),
        "present": (s / "meta.db").is_file() or n_bin > 0,
        "description": "20 millions de fichiers PE (10 M malveillants desarmes). Le depot GitHub fournit le "
                       "code ; les donnees (~8 To) sont sur S3 : importez meta.db (etiquettes) ou "
                       "telechargez un sous-ensemble d'echantillons.",
        "rows": n_bin, "size_bytes": (s / "meta.db").stat().st_size if (s / "meta.db").is_file() else size_bin,
        "missing": [] if (s / "meta.db").is_file() else ["meta.db (optionnel)"],
        "actions": [{"id": "ingest_sorel", "label": "Ingerer les echantillons telecharges"}] if n_bin else [],
    })

    # --- theZoo : clone local du depot GitHub
    z = settings.THEZOO_DIR / "repo"
    zn, zsize = _folder_files(z)
    out.append({
        "name": "thezoo", "title": "theZoo", "path": str(settings.THEZOO_DIR), "present": zn > 0,
        "description": "Collection de malwares (archives protegees, mot de passe 'infected'). Ingestion sans "
                       "execution : caracteristiques et empreintes conservees, fichiers extraits supprimes.",
        "rows": zn, "size_bytes": zsize, "missing": [] if zn else ["git clone dans data/datasets/thezoo/repo"],
        "actions": [{"id": "ingest_thezoo", "label": "Ingerer theZoo"}] if zn else [],
    })

    # --- vos propres dossiers etiquetes
    for key, folder, title in (("custom_malware", settings.CUSTOM_MALWARE_DIR, "Vos fichiers malveillants"),
                               ("custom_benign", settings.CUSTOM_BENIGN_DIR, "Vos fichiers sains")):
        n, size = _folder_files(folder)
        out.append({
            "name": key, "title": title, "path": str(folder), "present": n > 0,
            "description": "Deposez ici des fichiers etiquetes : ils alimentent les deux modeles.",
            "rows": n, "size_bytes": size, "missing": [],
            "actions": [{"id": "ingest_" + key.split("_")[1], "label": "Ingerer ce dossier"}] if n else [],
        })

    # --- EMBER2024 : format different (information seulement)
    out.append({
        "name": "ember2024", "title": "EMBER2024", "path": str(settings.DATASETS_DIR / "ember2024"),
        "present": False, "rows": 0, "size_bytes": 0, "missing": [],
        "description": "Caracteristiques version 3 (2568 valeurs) : format different de BODMAS, "
                       "pas encore utilisable. Voir le README du dossier.",
        "actions": [],
    })
    return out


def load_bodmas(bodmas_dir=None):
    """Charge BODMAS : (X float32 [n x 2381], y int8, horodatages float64, empreintes list).

    Verifie l'alignement entre le fichier .npz et les metadonnees (meme nombre de
    lignes ; une ligne est malveillante ssi elle a une famille) avant de continuer :
    un decalage fausserait silencieusement tout l'entrainement.
    """
    d = Path(bodmas_dir or settings.BODMAS_DIR)
    data = np.load(d / "bodmas.npz")
    X, y = data["X"].astype(np.float32, copy=False), data["y"].astype(np.int8)
    shas, stamps, fam = [], [], []
    with open(d / "bodmas_metadata.csv", newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            shas.append((row.get("sha256") or row["sha"]).lower())
            stamps.append(_parse_time(row["timestamp"]))
            fam.append(bool(row.get("family")))
    if len(shas) != len(y):
        raise ValueError(f"Metadonnees ({len(shas)}) et vecteurs ({len(y)}) ne sont pas alignes.")
    if not np.array_equal(np.array(fam, dtype=np.int8), y):
        raise ValueError("Les etiquettes du .npz ne correspondent pas aux familles des metadonnees.")
    return X, y, np.array(stamps, dtype=np.float64), shas


def _parse_time(text):
    """'2007-01-01 08:46:39+00:00' (ou '... UTC') -> secondes UNIX ; 0 si illisible."""
    try:
        return datetime.fromisoformat(text.replace(" UTC", "+00:00").strip()).timestamp()
    except ValueError:
        return 0.0
