"""Telecharge des flux publics de renseignement vers data/threat_intel/ (puis synchronise).

    python tools/fetch_feeds.py --abusech-key VOTRE_CLE [--phishtank-key CLE]

Flux : empreintes recentes de MalwareBazaar, liens URLhaus, IOC ThreatFox, base PhishTank.
Les adresses ci-dessous sont celles documentees par les services AU MOMENT DE L'ECRITURE ; elles
n'ont pas pu etre testees depuis l'environnement de developpement (reseau ferme). Si un flux
change d'adresse ou de format, modifiez simplement FEEDS : les lecteurs (cubernoyau/intel/loaders.py)
detectent le format automatiquement. Respectez les conditions d'utilisation de chaque service
(abuse.ch : usage equitable ; usage commercial = abonnement).
"""
import argparse
import gzip
import urllib.error
import urllib.request

import _common
from cubernoyau.config import settings
from cubernoyau.intel import loaders
from cubernoyau.intel.store import IntelStore

# nom -> (adresse, dossier de destination, cle necessaire ?)
FEEDS = {
    "mb_recent_sha256": ("https://bazaar.abuse.ch/export/txt/sha256/recent/", settings.INTEL_HASH_MALWARE_DIR, "abusech"),
    "urlhaus_online": ("https://urlhaus.abuse.ch/downloads/text_online/", settings.INTEL_URLS_DIR / "malware", "abusech"),
    "threatfox_recent": ("https://threatfox.abuse.ch/export/csv/recent/", settings.INTEL_URLS_DIR / "malware", "abusech"),
}


def download(url, headers):
    request = urllib.request.Request(url, headers={"User-Agent": settings.USER_AGENT, **headers})
    with urllib.request.urlopen(request, timeout=60) as response:       # noqa: S310
        return response.read()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--abusech-key", default="")
    ap.add_argument("--phishtank-key", default="")
    a = ap.parse_args()
    feeds = dict(FEEDS)
    if a.phishtank_key:
        feeds["phishtank"] = (f"http://data.phishtank.com/data/{a.phishtank_key}/online-valid.csv",
                              settings.INTEL_URLS_DIR / "phishing", "")
    for name, (url, folder, needs) in feeds.items():
        headers = {"Auth-Key": a.abusech_key} if needs == "abusech" and a.abusech_key else {}
        try:
            data = download(url, headers)
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            print(f"{name}: echec ({error})")
            continue
        folder.mkdir(parents=True, exist_ok=True)
        with gzip.open(folder / f"{name}.txt.gz", "wb") as handle:
            handle.write(data)
        print(f"{name}: {len(data) // 1024} Ko -> {folder}")
    store = IntelStore(_common.open_db())
    for row in loaders.sync_intel_folders(store):
        print(f"  importe {row['file']}: {row['added']} ajoutes")
    print(store.counts())
