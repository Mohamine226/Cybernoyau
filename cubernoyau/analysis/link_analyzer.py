"""Cubernoyau - Analyse statique de liens (URL).

Ce module n'ouvre JAMAIS les liens et n'effectue aucune requete reseau :
il examine uniquement la forme de l'adresse. Les indicateurs sont des
observations a verifier, pas des verdicts.
"""

import argparse
import ipaddress
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit

from cubernoyau.config.settings import BASE_DIR, DATA_DIR  # noqa: E402,F401
REPORT_DIR = DATA_DIR / "reports"

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc",
}

# TLD souvent observes dans des campagnes de phishing de masse.
# Un TLD n'est pas malveillant en soi : indicateur de faible poids.
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "country", "gq", "tk",
    "ml", "ga", "cf", "work", "support", "loan", "rest",
}

# Marque -> domaines legitimes (domaine enregistrable).
BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.fr"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "netflix": {"netflix.com"},
    "orange": {"orange.fr", "orange.com"},
    "mtn": {"mtn.com"},
    "moov": {"moov-africa.com"},
}

LURE_WORDS = {
    "login", "signin", "verify", "verification", "secure", "account",
    "update", "confirm", "password", "wallet", "bonus", "gagnant",
    "colis", "facture", "suspendu", "urgent",
}

# Suffixes a deux niveaux frequents (approximation sans base externe).
TWO_LEVEL_SUFFIXES = {
    "co.uk", "com.br", "com.au", "co.za", "com.bf", "gov.bf", "co.jp",
}


def registrable_domain(host):
    """Approximation du domaine enregistrable (sans liste publique)."""
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in TWO_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _indicator(code, severity, reason):
    """Construit un indicateur {code, severity, reason}."""
    return {"code": code, "severity": severity, "reason": reason}


def analyze_url(raw_url):
    """Analyse une URL sans jamais l'ouvrir."""
    raw_url = raw_url.strip()
    indicators = []
    to_parse = raw_url if "://" in raw_url else "http://" + raw_url

    try:
        parts = urlsplit(to_parse)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError as error:
        return {
            "url": raw_url,
            "assessment": "SUSPECT",
            "risk_indicators_count": 1,
            "risk_indicators": [_indicator(
                "MALFORMED_URL", "medium",
                f"Adresse mal formee : {error}")],
            "opened": False,
        }

    if not host:
        indicators.append(_indicator(
            "NO_HOST", "medium", "Aucun nom d'hote identifiable."))

    scheme = parts.scheme.lower()
    if scheme == "http":
        indicators.append(_indicator(
            "NO_HTTPS", "info",
            "Connexion non chiffree (http). Sensible si une saisie "
            "de mot de passe est demandee."))
    elif scheme not in {"https", "http"}:
        indicators.append(_indicator(
            "UNUSUAL_SCHEME", "medium",
            f"Schema inhabituel pour un lien web : {scheme}."))

    # Adresse IP a la place d'un nom de domaine.
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        if re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", host):
            is_ip = True
    if is_ip:
        indicators.append(_indicator(
            "IP_ADDRESS_HOST", "medium",
            "L'hote est une adresse IP et non un nom de domaine."))

    # Identifiants dans l'URL : http://paypal.com@site-inconnu.tk
    if parts.username is not None:
        indicators.append(_indicator(
            "USERINFO_IN_URL", "high",
            "L'URL contient un '@' : la partie avant '@' est ignoree "
            "par le navigateur, ce qui peut masquer la vraie destination."))

    if port not in (None, 80, 443):
        indicators.append(_indicator(
            "NON_STANDARD_PORT", "low",
            f"Port inhabituel : {port}."))

    domain = registrable_domain(host) if host and not is_ip else host
    labels = host.split(".") if host else []

    if host in URL_SHORTENERS or domain in URL_SHORTENERS:
        indicators.append(_indicator(
            "URL_SHORTENER", "medium",
            "Service de raccourcissement : la destination finale "
            "n'est pas visible."))

    # Domaine internationalise / homoglyphes.
    if any(label.startswith("xn--") for label in labels):
        indicators.append(_indicator(
            "PUNYCODE_DOMAIN", "high",
            "Nom de domaine internationalise (xn--) : peut imiter "
            "visuellement un domaine connu."))
    elif host and not host.isascii():
        indicators.append(_indicator(
            "NON_ASCII_DOMAIN", "high",
            "Caracteres non ASCII dans le domaine : risque d'imitation "
            "visuelle."))

    if len(labels) >= 5 and not is_ip:
        indicators.append(_indicator(
            "MANY_SUBDOMAINS", "low",
            f"{len(labels)} niveaux de sous-domaines."))

    tld = labels[-1] if labels and not is_ip else ""
    if tld in SUSPICIOUS_TLDS:
        indicators.append(_indicator(
            "SUSPICIOUS_TLD", "low",
            f"Extension .{tld} frequemment vue dans des campagnes "
            "abusives (non concluant a lui seul)."))

    # Marque connue dans l'hote mais domaine different.
    for brand, legit in BRAND_DOMAINS.items():
        if brand in host and domain not in legit and not is_ip:
            indicators.append(_indicator(
                "BRAND_IMPERSONATION_PATTERN", "high",
                f"Le nom '{brand}' apparait dans l'adresse, mais le "
                f"domaine reel est '{domain}'."))
            break

    if host.count("-") >= 3 and "xn--" not in host:
        indicators.append(_indicator(
            "MANY_HYPHENS", "low",
            "Nom de domaine avec de nombreux tirets."))

    decoded = unquote(parts.path + " " + parts.query).lower()
    hits = sorted(word for word in LURE_WORDS
                  if word in decoded or word in host)
    if len(hits) >= 2:
        indicators.append(_indicator(
            "LURE_KEYWORDS", "low",
            "Mots incitatifs : " + ", ".join(hits) + "."))

    if len(raw_url) > 150:
        indicators.append(_indicator(
            "VERY_LONG_URL", "low",
            f"Adresse tres longue ({len(raw_url)} caracteres)."))

    if re.search(r"%[0-9a-f]{2}", parts.netloc, re.I):
        indicators.append(_indicator(
            "ENCODED_HOST", "medium",
            "Caracteres encodes dans la partie hote."))

    # Redirection imbriquee : ?url=http://...
    if re.search(r"(=|/)https?(://|%3a%2f%2f)", parts.query, re.I):
        indicators.append(_indicator(
            "EMBEDDED_REDIRECT", "medium",
            "Une autre URL est integree dans les parametres "
            "(redirection possible)."))

    return {
        "url": raw_url,
        "host": host,
        "registrable_domain": domain,
        "assessment": assess(indicators),
        "risk_indicators_count": len(indicators),
        "risk_indicators": indicators,
        "opened": False,
        "notice": (
            "Analyse de la forme de l'adresse uniquement : aucune "
            "reputation en ligne n'a ete consultee et la page n'a pas "
            "ete ouverte. 'AUCUN_INDICATEUR_DETECTE' ne signifie pas "
            "que le lien est sur."
        ),
    }


WEIGHTS = {"info": 0, "low": 1, "medium": 2, "high": 4}


def assess(indicators):
    """Niveau global : aucun indicateur / suspect / risque eleve."""
    score = sum(WEIGHTS.get(i["severity"], 0) for i in indicators)
    if any(i["severity"] == "high" for i in indicators) and score >= 6:
        return "RISQUE_ELEVE"
    if score >= 4:
        return "RISQUE_ELEVE"
    if score >= 1:
        return "SUSPECT"
    return "AUCUN_INDICATEUR_DETECTE"


def analyze_urls(urls):
    """Analyse une liste de liens et retourne un bilan."""
    results = [analyze_url(url) for url in urls if url.strip()]
    return {
        "analysis_time": datetime.now().astimezone().isoformat(),
        "links_examined": len(results),
        "suspect": sum(r["assessment"] == "SUSPECT" for r in results),
        "high_risk": sum(r["assessment"] == "RISQUE_ELEVE" for r in results),
        "links": results,
    }


def save_report(data):
    """Enregistre le rapport JSON dans data/reports/."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report = REPORT_DIR / f"link_analysis_{stamp}.json"
    with report.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Cubernoyau - Analyse statique de liens (sans ouverture)")
    parser.add_argument("urls", nargs="*", help="URL a examiner")
    parser.add_argument("--file", help="Fichier texte : une URL par ligne")
    args = parser.parse_args()

    urls = list(args.urls)
    if args.file:
        urls += Path(args.file).read_text(encoding="utf-8").splitlines()
    if not urls:
        parser.error("Fournir au moins une URL ou --file")

    summary = analyze_urls(urls)
    report = save_report(summary)

    print("\n=== ANALYSE DE LIENS CUBERNOYAU ===")
    for item in summary["links"]:
        print(f"\n{item['url']}\n  Evaluation : {item['assessment']}")
        for ind in item["risk_indicators"]:
            print(f"  - [{ind['severity']}] {ind['code']} : {ind['reason']}")
    print("\nLiens ouverts : non")
    print(f"Rapport : {report}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeDecodeError) as error:
        print(f"Erreur : {error}")
        sys.exit(1)
