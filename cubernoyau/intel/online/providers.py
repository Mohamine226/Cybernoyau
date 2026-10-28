"""Clients des services externes. Chaque methode retourne la reponse BRUTE (dict) ;
c'est `interpret.py` qui la transforme en verdict. Separer les deux permet de tester
l'interpretation avec des reponses reelles enregistrees.

Documentation officielle des API :
    MalwareBazaar  https://bazaar.abuse.ch/api/            (POST mb-api.abuse.ch/api/v1/)
    ThreatFox      https://threatfox.abuse.ch/api/         (POST threatfox-api.abuse.ch/api/v1/)
    URLhaus        https://urlhaus.abuse.ch/api/           (POST urlhaus-api.abuse.ch/v1/)
    PhishTank      https://phishtank.org/developer_info.php
    VirusTotal     https://docs.virustotal.com/reference   (v3)
Les trois services abuse.ch partagent UNE cle gratuite (https://auth.abuse.ch) envoyee
dans l'en-tete `Auth-Key`.
"""

import base64

from cubernoyau.intel.online.base import ProviderError

MB_URL = "https://mb-api.abuse.ch/api/v1/"
TF_URL = "https://threatfox-api.abuse.ch/api/v1/"
UH_URL = "https://urlhaus-api.abuse.ch/v1/"
PT_URL = "https://checkurl.phishtank.com/checkurl/"
VT_URL = "https://www.virustotal.com/api/v3/"

# Ce que chaque service recoit : affiche dans l'interface pour que l'utilisateur sache.
WHAT_IS_SENT = {
    "malwarebazaar": "l'empreinte SHA-256 du fichier",
    "threatfox": "l'empreinte SHA-256 du fichier, ou le lien / domaine examine",
    "urlhaus": "le lien, le domaine ou l'empreinte SHA-256 examine",
    "phishtank": "le lien examine",
    "virustotal": "l'empreinte SHA-256 du fichier ou le lien examine",
}


class AbuseCh:
    """MalwareBazaar + ThreatFox + URLhaus (meme cle, memes conventions)."""

    def __init__(self, client, key):
        self.http, self.key = client, key

    def _headers(self):
        """En-tete d'authentification abuse.ch (leve ProviderError sans cle)."""
        if not self.key:
            raise ProviderError("Cle abuse.ch manquante (gratuite sur auth.abuse.ch).")
        return {"Auth-Key": self.key}

    # --- MalwareBazaar : base d'echantillons de malwares (tout fichier present EST un malware)
    def bazaar_hash(self, sha256):
        """MalwareBazaar : informations sur un echantillon par SHA-256."""
        return self.http.request("POST", MB_URL, self._headers(), form={"query": "get_info", "hash": sha256})

    # --- ThreatFox : indicateurs de compromission (IOC) rattaches a une famille
    def threatfox_hash(self, sha256):
        """ThreatFox : indicateurs associes a une empreinte."""
        return self.http.request("POST", TF_URL, self._headers(),
                                 payload={"query": "search_hash", "hash": sha256})

    def threatfox_ioc(self, term):
        """ThreatFox : recherche d'un lien, domaine ou adresse IP."""
        return self.http.request("POST", TF_URL, self._headers(),
                                 payload={"query": "search_ioc", "search_term": term, "exact_match": True})

    # --- URLhaus : liens qui diffusent des malwares
    def urlhaus_url(self, url):
        """URLhaus : etat d'un lien precis."""
        return self.http.request("POST", UH_URL + "url/", self._headers(), form={"url": url})

    def urlhaus_host(self, host):
        """URLhaus : liens connus pour un domaine."""
        return self.http.request("POST", UH_URL + "host/", self._headers(), form={"host": host})

    def urlhaus_payload(self, sha256):
        """URLhaus : fichier (par SHA-256) diffuse par des liens connus."""
        return self.http.request("POST", UH_URL + "payload/", self._headers(),
                                 form={"sha256_hash": sha256})


class PhishTank:
    """Verification d'un lien dans la base de hameconnage PhishTank (cle optionnelle)."""

    def __init__(self, client, key=""):
        self.http, self.key = client, key

    def check(self, url):
        """PhishTank : le lien est-il un hameconnage verifie ?"""
        form = {"url": base64.b64encode(url.encode()).decode(), "format": "json"}
        if self.key:
            form["app_key"] = self.key
        return self.http.request("POST", PT_URL, form=form)


class VirusTotal:
    """VirusTotal v3 : nombre de moteurs antivirus qui detectent un fichier ou un lien."""

    def __init__(self, client, key):
        self.http, self.key = client, key

    def _headers(self):
        """En-tete d'authentification VirusTotal."""
        if not self.key:
            raise ProviderError("Cle VirusTotal manquante.")
        return {"x-apikey": self.key}

    def file(self, sha256):
        """VirusTotal : bilan des moteurs antivirus pour une empreinte."""
        return self.http.request("GET", VT_URL + f"files/{sha256}", self._headers())

    def url(self, url):
        # Identifiant VirusTotal d'un lien : base64 "url-safe" sans les "=" de fin.
        """VirusTotal : bilan des moteurs antivirus pour un lien."""
        ident = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return self.http.request("GET", VT_URL + f"urls/{ident}", self._headers())
