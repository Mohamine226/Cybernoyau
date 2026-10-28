"""Normalisation des liens.

Deux ecritures du meme lien doivent donner la meme cle pour qu'une liste de
liens malveillants (URLhaus, PhishTank...) reconnaisse un lien saisi autrement :
 - le schema (http/https) et la casse de l'hote n'ont pas d'importance ;
 - les ports par defaut (80, 443), le fragment (#...) et le "/" final sont ignores ;
 - le chemin et la requete (?a=b) sont conserves tels quels (ils font la difference
   entre une page saine et la page piegee d'un meme site).
"""

from urllib.parse import urlsplit

SCHEMES = ("http://", "https://", "ftp://")


def split_host(raw):
    """Retourne l'hote (minuscules, sans port) d'un lien ou d'un nom de domaine, ou ''."""
    raw = raw.strip()
    parts = urlsplit(raw if "://" in raw else "http://" + raw)
    try:
        return (parts.hostname or "").lower()
    except ValueError:  # lien mal forme (ex. crochets IPv6 invalides)
        return ""


def normalize_url(raw):
    """Retourne (cle, hote) ; cle = 'hote[:port]/chemin?requete' ou '' si inexploitable."""
    raw = raw.strip().strip("\"'<>")
    if not raw:
        return "", ""
    parts = urlsplit(raw if "://" in raw else "http://" + raw)
    try:
        host, port = (parts.hostname or "").lower(), parts.port
    except ValueError:
        return "", ""
    if not host:
        return "", ""
    hostport = host if port in (None, 80, 443) else f"{host}:{port}"
    path = parts.path.rstrip("/")
    query = f"?{parts.query}" if parts.query else ""
    return f"{hostport}{path}{query}", host
