"""Reglages de Mougle Protect / Cubernoyau.

Toutes les valeurs ont un defaut raisonnable ; chacune peut etre changee par une
variable d'environnement (prefixe CUBERNOYAU_) sans modifier le code. Ce module
est le SEUL endroit qui connait l'emplacement des dossiers : les autres modules
importent les constantes ci-dessous au lieu de reconstruire des chemins.

Disposition du projet (voir README.md) ::

    cubernoyau/            le noyau : analyse, detection, renseignement, entrainement
    server/                l'API FastAPI
    frontend/              l'interface web
    data/                  TOUTES les donnees (jeux d'entrainement, listes, modeles)
    tools/                 scripts en ligne de commande
    third_party/           code externe conserve tel quel (SOREL-20M, Apache-2.0)
"""

import os
from pathlib import Path

# --------------------------------------------------------------------------
# Dossiers
# --------------------------------------------------------------------------
# Racine du projet : ce fichier est dans cubernoyau/config/, donc deux niveaux au-dessus.
BASE_DIR = Path(__file__).resolve().parents[2]

# Dossier des donnees. Le deplacer (ex. vers un gros disque) : CUBERNOYAU_DATA=D:\donnees
DATA_DIR = Path(os.environ.get("CUBERNOYAU_DATA", BASE_DIR / "data"))

# Base SQLite : alertes, historique des analyses, listes de hachages/liens, caches.
DB_PATH = Path(os.environ.get("CUBERNOYAU_DB", DATA_DIR / "cubernoyau.db"))

# Jeux de donnees d'entrainement (un sous-dossier par jeu, voir leur README.md).
DATASETS_DIR = DATA_DIR / "datasets"
BODMAS_DIR = DATASETS_DIR / "bodmas"
SOREL_DIR = DATASETS_DIR / "sorel20m"
THEZOO_DIR = DATASETS_DIR / "thezoo"
CUSTOM_MALWARE_DIR = DATASETS_DIR / "custom" / "malware"
CUSTOM_BENIGN_DIR = DATASETS_DIR / "custom" / "benign"

# Listes de renseignement (empreintes et liens connus) synchronisees automatiquement.
INTEL_DIR = DATA_DIR / "threat_intel"
INTEL_HASH_MALWARE_DIR = INTEL_DIR / "hashes" / "malware"
INTEL_HASH_BENIGN_DIR = INTEL_DIR / "hashes" / "benign"
INTEL_URLS_DIR = INTEL_DIR / "urls"

# Modeles entraines et regles personnalisees.
MODELS_DIR = DATA_DIR / "models"
EMBER_DIR = MODELS_DIR / "ember"          # modeles LightGBM (format texte) + metriques JSON
RULES_DIR = DATA_DIR / "rules"

# --------------------------------------------------------------------------
# Serveur et acces
# --------------------------------------------------------------------------
# Jeton d'acces : obligatoire des que le serveur ecoute hors de 127.0.0.1
# (mode telephone Android : `python main.py --lan`).
ACCESS_TOKEN = os.environ.get("CUBERNOYAU_TOKEN", "")

# Surveillance continue : secondes entre deux cycles, et demarrage automatique.
MONITOR_INTERVAL = float(os.environ.get("CUBERNOYAU_INTERVAL", "10"))
AUTOSTART = os.environ.get("CUBERNOYAU_AUTOSTART", "1") != "0"

# --------------------------------------------------------------------------
# Analyse de fichiers
# --------------------------------------------------------------------------
# 0 = aucune limite de taille : les fichiers sont lus en flux, jamais charges en memoire.
MAX_UPLOAD_MB = int(os.environ.get("CUBERNOYAU_MAX_UPLOAD_MB", "0"))
# Octets examines en profondeur (motifs, IOC) pour un tres gros fichier : debut + fin.
# Le hachage et l'entropie portent toujours sur la totalite du fichier.
MAX_CONTENT_SCAN_MB = int(os.environ.get("CUBERNOYAU_SCAN_MB", "48"))
MAX_DIRECTORY_FILES = int(os.environ.get("CUBERNOYAU_MAX_DIR_FILES", "1000"))
MAX_LINKS_PER_REQUEST = 100
# Nombre maximal de nouveaux executables analyses en profondeur par cycle de surveillance.
MAX_NEW_APPS_PER_CYCLE = 6

# --------------------------------------------------------------------------
# Alertes
# --------------------------------------------------------------------------
# Delai avant de re-signaler le meme element (evite le spam d'alertes identiques).
ALERT_COOLDOWN_SECONDS = int(os.environ.get("CUBERNOYAU_COOLDOWN", "600"))

# --------------------------------------------------------------------------
# Entrainement
# --------------------------------------------------------------------------
MIN_TRAIN_SAMPLES = 30          # echantillons etiquetes minimum (modele RandomForest)
MIN_PER_CLASS = 10              # minimum par classe (sain / malveillant)
# Reentrainement automatique des que ce nombre de nouveaux retours utilisateur est atteint.
AUTO_TRAIN_MIN_NEW = int(os.environ.get("CUBERNOYAU_AUTO_TRAIN_MIN_NEW", "20"))
# Taille maximale (octets) d'un fichier pour lequel on calcule le vecteur EMBER.
EMBER_MAX_FILE_BYTES = 100 * 1024 * 1024

# --------------------------------------------------------------------------
# API externes d'analyse (MalwareBazaar, ThreatFox, URLhaus, PhishTank, VirusTotal)
# --------------------------------------------------------------------------
# DESACTIVEES par defaut : elles envoient des empreintes SHA-256 / liens a un tiers.
# Jamais le contenu d'un fichier. Les cles se saisissent dans l'interface (page
# "Connexions") ou par variables d'environnement ci-dessous.
ONLINE_TIMEOUT_SECONDS = float(os.environ.get("CUBERNOYAU_ONLINE_TIMEOUT", "8"))
ONLINE_CACHE_HOURS = int(os.environ.get("CUBERNOYAU_ONLINE_CACHE_HOURS", "24"))
ENV_KEYS = {                                  # fournisseur -> variable d'environnement
    "abusech": "CUBERNOYAU_ABUSECH_KEY",      # une cle unique pour MalwareBazaar/ThreatFox/URLhaus
    "phishtank": "CUBERNOYAU_PHISHTANK_KEY",  # optionnelle (limite les quotas)
    "virustotal": "CUBERNOYAU_VT_KEY",        # optionnelle
}
USER_AGENT = "MougleProtect/2.0 (+local)"     # identification demandee par plusieurs services


def get_watch_dirs():
    """Dossiers surveilles pour detecter les modifications massives de fichiers.

    Par defaut : Telechargements, Documents et Bureau de l'utilisateur (ceux qui
    existent). Personnalisable : CUBERNOYAU_WATCH="C:\\a;D:\\b" (separateur du systeme).
    """
    custom = os.environ.get("CUBERNOYAU_WATCH")
    if custom:
        candidates = [Path(p) for p in custom.split(os.pathsep) if p]
    else:
        home = Path.home()
        candidates = [home / "Downloads", home / "Documents", home / "Desktop"]
    return [p for p in candidates if p.is_dir()]
