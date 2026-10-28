"""Facade des API externes : reglages, cles, cache, interrogation, interpretation.

Usage typique (voir server/scans.py) ::

    online = OnlineIntel(db, store)
    result = online.check_hash(sha256)     # {"enabled", "verdicts", "indicators", "summary"}
    result = online.check_url("http://...")

Garde-fous :
  * interrupteur general desactive par defaut (opt-in explicite) ;
  * chaque service peut etre coupe separement ;
  * un service en panne ne bloque jamais l'analyse : son verdict est "error" ;
  * les reponses valides sont gardees ONLINE_CACHE_HOURS heures (pas de requete inutile,
    respect des quotas) ; les erreurs ne sont jamais mises en cache ;
  * un budget de temps total evite qu'une liste de liens ne fige l'interface.
"""

import os
import time
from urllib.parse import urlsplit

from cubernoyau.config import settings
from cubernoyau.intel.online import interpret as I
from cubernoyau.intel.online.base import HttpClient, ProviderError
from cubernoyau.intel.online.providers import (AbuseCh, PhishTank, VirusTotal,
                                               WHAT_IS_SENT)

# id du service -> (titre, groupe de cle, cle obligatoire ?, page d'inscription)
PROVIDERS = {
    "malwarebazaar": ("MalwareBazaar", "abusech", True, "https://auth.abuse.ch"),
    "threatfox": ("ThreatFox", "abusech", True, "https://auth.abuse.ch"),
    "urlhaus": ("URLhaus", "abusech", True, "https://auth.abuse.ch"),
    "phishtank": ("PhishTank", "phishtank", False, "https://phishtank.org/api_info.php"),
    "virustotal": ("VirusTotal", "virustotal", True, "https://www.virustotal.com/gui/join-us"),
}


class OnlineIntel:
    """Facade des services externes : reglages, cles, cache, interrogation et interpretation."""
    def __init__(self, db, store, transport=None):
        self.db, self.store = db, store
        self.http = HttpClient(transport)

    # ------------------------------------------------------------------ reglages
    def key(self, group):
        """Cle d'un groupe : la variable d'environnement l'emporte sur la valeur enregistree."""
        return os.environ.get(settings.ENV_KEYS[group]) or self.db.get_setting(f"online.key.{group}", "")

    def master_enabled(self):
        """True si l'utilisateur a autorise les services en ligne."""
        return self.db.get_setting("online.master", "0") == "1"

    def provider_enabled(self, pid):
        """Service utilisable : interrupteur general ON, service ON et cle presente si requise."""
        _title, group, needs_key, _url = PROVIDERS[pid]
        return (self.master_enabled() and self.db.get_setting(f"online.enable.{pid}", "1") != "0"
                and (not needs_key or bool(self.key(group))))

    def get_settings(self):
        """Etat pour l'interface. Les cles ne sont JAMAIS renvoyees : seulement les 4 derniers caracteres."""
        items = []
        for pid, (title, group, needs_key, signup) in PROVIDERS.items():
            key = self.key(group)
            items.append({
                "id": pid, "title": title, "group": group, "needs_key": needs_key,
                "configured": bool(key) or not needs_key, "key_hint": ("••••" + key[-4:]) if key else "",
                "enabled": self.db.get_setting(f"online.enable.{pid}", "1") != "0",
                "usable": self.provider_enabled(pid), "what_is_sent": WHAT_IS_SENT[pid], "signup": signup,
            })
        return {"master": self.master_enabled(), "providers": items,
                "cache_hours": settings.ONLINE_CACHE_HOURS, "timeout": settings.ONLINE_TIMEOUT_SECONDS,
                "privacy": "Seuls des empreintes SHA-256, des liens ou des noms de domaine sont envoyes, "
                           "jamais le contenu d'un fichier."}

    def update_settings(self, master=None, enabled=None, keys=None):
        """Modifie les reglages. keys = {groupe: valeur} ; une valeur vide efface la cle."""
        if master is not None:
            self.db.set_setting("online.master", "1" if master else "0")
        for pid, flag in (enabled or {}).items():
            if pid in PROVIDERS:
                self.db.set_setting(f"online.enable.{pid}", "1" if flag else "0")
        for group, value in (keys or {}).items():
            if group in settings.ENV_KEYS:
                self.db.set_setting(f"online.key.{group}", (value or "").strip())
        return self.get_settings()

    # ------------------------------------------------------------------ outils internes
    def _clients(self):
        """Instancie les clients avec les cles courantes."""
        abusech = AbuseCh(self.http, self.key("abusech"))
        return abusech, PhishTank(self.http, self.key("phishtank")), VirusTotal(self.http, self.key("virustotal"))

    def _cached(self, pid, key, call, interpret, deadline):
        """Interroge un service (ou lit le cache) et retourne un verdict. Ne leve jamais d'exception."""
        if not self.provider_enabled(pid):
            return None
        raw = self.store.cache_get(pid, key, settings.ONLINE_CACHE_HOURS)
        if raw is None:
            if deadline and time.monotonic() > deadline:
                return I.skipped_verdict(pid, "Non interroge (delai total depasse).")
            try:
                raw = call()
            except ProviderError as error:
                return I.error_verdict(pid, str(error))
            self.store.cache_set(pid, key, raw)         # seules les reponses valides sont gardees
        try:
            return interpret(raw)
        except Exception as error:                      # reponse de forme inattendue
            return I.error_verdict(pid, f"reponse non comprise ({type(error).__name__})")

    @staticmethod
    def _package(verdicts):
        """Assemble verdicts, synthese et indicateurs."""
        verdicts = [v for v in verdicts if v]
        return {"enabled": True, "verdicts": verdicts, "summary": I.summarize(verdicts),
                "indicators": [v["indicator"] for v in verdicts if v["indicator"]]}

    # ------------------------------------------------------------------ interrogation
    def check_hash(self, sha256, budget_seconds=20):
        """Interroge MalwareBazaar, ThreatFox, URLhaus et VirusTotal pour une empreinte."""
        if not self.master_enabled():
            return {"enabled": False, "verdicts": [], "indicators": [], "summary": None}
        sha = sha256.lower()
        ab, _pt, vt = self._clients()
        end = time.monotonic() + budget_seconds
        return self._package([
            self._cached("malwarebazaar", sha, lambda: ab.bazaar_hash(sha),
                         lambda r: I.malwarebazaar_hash(r, sha), end),
            self._cached("threatfox", sha, lambda: ab.threatfox_hash(sha),
                         lambda r: I.threatfox_hash(r, sha), end),
            self._cached("urlhaus", "p:" + sha, lambda: ab.urlhaus_payload(sha),
                         lambda r: I.urlhaus_payload(r, sha), end),
            self._cached("virustotal", "f:" + sha, lambda: vt.file(sha),
                         lambda r: I.virustotal_file(r, sha), end),
        ])

    def check_url(self, url, budget_seconds=20):
        """Interroge URLhaus (lien puis domaine), ThreatFox, PhishTank et VirusTotal pour un lien."""
        if not self.master_enabled():
            return {"enabled": False, "verdicts": [], "indicators": [], "summary": None}
        ab, pt, vt = self._clients()
        host = (urlsplit(url if "://" in url else "http://" + url).hostname or "").lower()
        end = time.monotonic() + budget_seconds
        verdicts = [
            self._cached("urlhaus", "u:" + url, lambda: ab.urlhaus_url(url),
                         lambda r: I.urlhaus_url(r, url), end),
        ]
        # Domaine : seulement si le lien exact n'est pas deja connu (evite une requete inutile).
        if host and not (verdicts[0] and verdicts[0]["status"] == "malicious"):
            verdicts.append(self._cached("urlhaus", "h:" + host, lambda: ab.urlhaus_host(host),
                                         lambda r: I.urlhaus_host(r, host), end))
        verdicts += [
            self._cached("threatfox", "i:" + url, lambda: ab.threatfox_ioc(url),
                         lambda r: I.threatfox_ioc(r, url), end),
            self._cached("phishtank", url, lambda: pt.check(url), lambda r: I.phishtank(r, url), end),
            self._cached("virustotal", "u:" + url, lambda: vt.url(url),
                         lambda r: I.virustotal_url(r, url), end),
        ]
        return self._package(verdicts)

    def test(self, pid):
        """Verifie qu'un service repond et que la cle est acceptee (requete inoffensive)."""
        if pid not in PROVIDERS:
            return {"ok": False, "message": "Service inconnu."}
        title, group, needs_key, _ = PROVIDERS[pid]
        if needs_key and not self.key(group):
            return {"ok": False, "message": f"Aucune cle enregistree pour {title}."}
        ab, pt, vt = self._clients()
        probe = "0" * 64                                  # empreinte neutre : doit etre "inconnue"
        try:
            if pid == "malwarebazaar":
                ab.bazaar_hash(probe)
            elif pid == "threatfox":
                ab.threatfox_hash(probe)
            elif pid == "urlhaus":
                ab.urlhaus_host("example.com")
            elif pid == "phishtank":
                pt.check("http://example.com/")
            else:
                vt.file(probe)
        except ProviderError as error:
            return {"ok": False, "message": str(error)}
        return {"ok": True, "message": f"{title} repond correctement."}
