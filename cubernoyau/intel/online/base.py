"""Client HTTP minimal (bibliotheque standard : aucune dependance) pour les API externes.

Le transport est une simple fonction `transport(method, url, headers, body, timeout)`
qui retourne (code_http, octets). En production c'est `urllib_transport` ; les tests
fournissent un faux transport qui renvoie des reponses enregistrees, ce qui permet de
verifier toute la chaine (appel -> interpretation -> indicateurs) sans reseau.
"""

import json
import urllib.error
import urllib.parse
import urllib.request

from cubernoyau.config import settings


class ProviderError(Exception):
    """Erreur d'un service externe (reseau, authentification, quota, reponse invalide)."""


def urllib_transport(method, url, headers, body, timeout):
    """Transport reel. Retourne (code, octets) meme pour les codes d'erreur HTTP (401, 404, 429...)."""
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:   # noqa: S310 (URL fixees par nous)
            return response.status, response.read(5_000_000)                 # reponse limitee a 5 Mo
    except urllib.error.HTTPError as error:
        return error.code, error.read(200_000)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ProviderError(f"Service injoignable : {getattr(error, 'reason', error)}") from error


class HttpClient:
    """Client HTTP des services externes : delai maximum, identification, conversion des erreurs."""
    def __init__(self, transport=None, timeout=None):
        self.transport = transport or urllib_transport
        self.timeout = timeout or settings.ONLINE_TIMEOUT_SECONDS

    def request(self, method, url, headers=None, form=None, payload=None):
        """Envoie une requete ; `form` = champs de formulaire, `payload` = corps JSON.

        Retourne l'objet JSON de la reponse. Leve ProviderError pour tout probleme
        (y compris 401 / 403 : cle absente ou refusee, et 429 : quota depasse).
        """
        head = {"User-Agent": settings.USER_AGENT, "Accept": "application/json"}
        head.update(headers or {})
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
            head["Content-Type"] = "application/x-www-form-urlencoded"
        elif payload is not None:
            body = json.dumps(payload).encode()
            head["Content-Type"] = "application/json"
        status, raw = self.transport(method, url, head, body, self.timeout)
        if status in (401, 403):
            raise ProviderError("Acces refuse : cle absente ou invalide.")
        if status == 429:
            raise ProviderError("Quota depasse : reessayez plus tard.")
        if status >= 500:
            raise ProviderError(f"Le service a un probleme (HTTP {status}).")
        if status == 404:
            return {"_http": 404}
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except ValueError as error:
            raise ProviderError("Reponse illisible du service.") from error
        return data if isinstance(data, dict) else {"data": data}
