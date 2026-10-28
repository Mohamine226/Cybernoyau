"""Lecture des listes de renseignement et synchronisation du dossier data/threat_intel.

Formats acceptes (detectes automatiquement, fichiers .txt / .csv / .json-lignes, avec ou sans .gz) :

Empreintes (dossiers hashes/malware et hashes/benign)
    - une empreinte SHA-256 par ligne ;
    - CSV quelconque contenant une colonne SHA-256 (export MalwareBazaar, URLhaus
      "payloads", ThreatFox...). Le champ qui suit l'empreinte, s'il est court,
      devient l'etiquette (famille) ;
    - les lignes qui commencent par # sont ignorees.

Liens (dossier urls/, sous-dossiers malware/ et phishing/)
    - URLhaus (texte ou CSV), PhishTank (CSV), ThreatFox (CSV), liste simple.
    Le premier lien trouve dans chaque ligne est retenu ; les liens tronques par
    une page web ("...") sont ignores.
"""

import csv
import gzip
import io
import re
from pathlib import Path

from cubernoyau.config import settings

SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
URL_RE = re.compile(r"(?:https?|ftp)://[^\s\",<>']+", re.IGNORECASE)
# Mots qui, dans une ligne ThreatFox, indiquent un serveur de commande (C2).
C2_HINTS = ("botnet_cc", "c2", "command")


def open_text(path):
    """Ouvre un fichier texte, decompresse a la volee s'il se termine par .gz."""
    path = Path(path)
    if path.suffix.lower() == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="ignore")
    return open(path, "r", encoding="utf-8", errors="ignore")


def fingerprint(path):
    """Empreinte rapide d'un fichier (taille + date) pour savoir s'il a change."""
    st = Path(path).stat()
    return f"{st.st_size}:{int(st.st_mtime)}"


# --------------------------------------------------------------------------- empreintes
def parse_hash_lines(lines, default_source):
    """Genere (sha256, etiquette|None) pour chaque empreinte trouvee dans `lines`."""
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = SHA256_RE.search(line)
        if not match:
            continue
        label = None
        # Champ qui suit l'empreinte : etiquette possible (ex. "bodmas,wacatac").
        tail = line[match.end():].lstrip(" ,;\t\"")
        if tail:
            candidate = re.split(r"[,;\t\"]", tail, maxsplit=1)[0].strip()
            # On ecarte ce qui ressemble a une autre empreinte, une date ou un nombre.
            if (candidate and len(candidate) <= 60 and not SHA256_RE.search(candidate)
                    and not re.fullmatch(r"[\d\-: .UTC]+", candidate)):
                label = candidate
        yield match.group(0).lower(), label


# --------------------------------------------------------------------------- liens
def parse_url_lines(lines, default_kind):
    """Genere (lien, genre) ; genre = malware | phishing | c2."""
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = URL_RE.search(line)
        if not match:
            continue
        url = match.group(0)
        if url.endswith("..."):          # lien tronque par un affichage web : inexploitable
            continue
        url = url.rstrip(".,;)")
        kind = default_kind
        low = line.lower()
        if any(h in low for h in C2_HINTS) and "payload_delivery" not in low:
            kind = "c2"
        elif "phish" in low:
            kind = "phishing"
        yield url, kind


# --------------------------------------------------------------------------- synchronisation
def _iter_files(directory):
    """Fichiers de listes d'un dossier (README exclus)."""
    d = Path(directory)
    if not d.is_dir():
        return []
    return sorted(p for p in d.rglob("*")
                  if p.is_file() and p.name.lower() != "readme.md"
                  and p.suffix.lower() in (".txt", ".csv", ".gz", ".list", ".json", ".jsonl"))


def sync_intel_folders(store, force=False):
    """Importe les fichiers nouveaux ou modifies de data/threat_intel/.

    Retourne la liste des fichiers traites : [{"file", "kind", "rows", "added"}].
    Un fichier deja importe et inchange est ignore (sauf force=True), ce qui rend
    l'appel peu couteux au demarrage meme avec des listes de plusieurs millions de lignes.
    """
    report = []

    def run(path, kind, importer):
        """Importe un fichier si nouveau ou modifie."""
        fp = fingerprint(path)
        if not force and store.file_is_current(path, fp):
            return
        with open_text(path) as handle:
            rows, added = importer(handle, path)
        store.mark_file(path, fp, kind, rows)
        report.append({"file": str(path.relative_to(settings.INTEL_DIR)), "kind": kind,
                       "rows": rows, "added": added})

    def hashes(label_kind):
        """Fabrique l'importeur d'une liste d'empreintes."""
        def importer(handle, path):
            source = path.name.split(".")[0]
            pairs = list(parse_hash_lines(handle, source))
            if label_kind == "malware":
                added = store.add_malware_hashes((h, lab or source, source) for h, lab in pairs)
            else:
                added = store.add_benign_hashes((h, source) for h, _ in pairs)
            return len(pairs), added
        return importer

    def urls(default_kind):
        """Fabrique l'importeur d'une liste de liens."""
        def importer(handle, path):
            source = path.name.split(".")[0]
            pairs = list(parse_url_lines(handle, default_kind))
            added_u, added_h = store.add_urls((u, k, source) for u, k in pairs)
            return len(pairs), added_u + added_h
        return importer

    for p in _iter_files(settings.INTEL_HASH_MALWARE_DIR):
        run(p, "hashes:malware", hashes("malware"))
    for p in _iter_files(settings.INTEL_HASH_BENIGN_DIR):
        run(p, "hashes:benign", hashes("benign"))
    for p in _iter_files(settings.INTEL_URLS_DIR):
        default = "phishing" if "phish" in str(p).lower() else "malware"
        run(p, f"urls:{default}", urls(default))
    return report


# --------------------------------------------------------------------------- BODMAS -> listes
def bodmas_to_intel_files(bodmas_dir=None, out_dir=None):
    """Transforme les metadonnees BODMAS en deux listes d'empreintes (plus legeres que le .npz).

    - hashes/malware/bodmas.csv.gz : sha256,etiquette (famille, sinon categorie)
    - hashes/benign/bodmas.txt.gz  : sha256
    Aucune dependance a numpy : seules les colonnes du CSV de metadonnees sont lues
    (une ligne est "malveillante" si elle a une famille, ce qui correspond exactement
    au vecteur y du fichier .npz - verifie a l'import des donnees).
    """
    bodmas_dir = Path(bodmas_dir or settings.BODMAS_DIR)
    out = Path(out_dir or settings.INTEL_DIR / "hashes")
    meta = bodmas_dir / "bodmas_metadata.csv"
    if not meta.is_file():
        raise FileNotFoundError(f"Fichier introuvable : {meta}")
    categories = {}
    cat_file = bodmas_dir / "bodmas_malware_category.csv"
    if cat_file.is_file():
        with open(cat_file, newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                categories[row["sha256"].lower()] = row["category"]
    (out / "malware").mkdir(parents=True, exist_ok=True)
    (out / "benign").mkdir(parents=True, exist_ok=True)
    n_mal = n_ben = 0
    with open(meta, newline="", encoding="utf-8") as handle, \
            gzip.open(out / "malware" / "bodmas.csv.gz", "wt", encoding="utf-8") as fm, \
            gzip.open(out / "benign" / "bodmas.txt.gz", "wt", encoding="utf-8") as fb:
        fm.write("# BODMAS - empreintes de malwares (sha256,famille ou categorie)\n")
        fb.write("# BODMAS - empreintes de fichiers sains\n")
        for row in csv.DictReader(handle):
            sha = (row.get("sha256") or row["sha"]).lower()
            if row.get("family"):
                fm.write(f"{sha},{row['family'] or categories.get(sha, 'malware')}\n")
                n_mal += 1
            else:
                fb.write(sha + "\n")
                n_ben += 1
    return {"malware": n_mal, "benign": n_ben}
