"""Interpretation des reponses des services externes.

Un service externe repond avec son propre vocabulaire (query_status, url_status,
confidence_level, last_analysis_stats...). Ce module le traduit en un VERDICT
commun, lisible par une personne non specialiste, et en INDICATEURS de risque que le
moteur de score sait combiner avec le reste de l'analyse.

Regles d'interpretation (a connaitre, elles sont volontairement prudentes) :
  * "inconnu" ne veut JAMAIS dire "sain" : un fichier recent ou rare n'est dans aucune
    base. Seul un resultat positif est une information forte.
  * MalwareBazaar ne contient que des malwares : y etre present suffit pour conclure.
  * VirusTotal : 5 moteurs ou plus = malveillant (meme seuil que le jeu EMBER2024) ;
    1 a 4 detections peuvent etre des faux positifs, d'ou une gravite faible.
  * URLhaus : un lien "online" diffuse un malware MAINTENANT (critique) ; "offline"
    a deja servi un malware (eleve) mais ne le fait plus.
  * PhishTank : seul un hameconnage verifie ET toujours actif est critique.
  * ThreatFox : la gravite suit le niveau de confiance (0-100) donne par le rapporteur.

Verdict : {"provider", "title", "status", "headline", "advice", "reference", "details", "indicator"}
status : malicious | suspicious | clean | unknown | error
"""

TITLES = {"malwarebazaar": "MalwareBazaar", "threatfox": "ThreatFox", "urlhaus": "URLhaus",
          "phishtank": "PhishTank", "virustotal": "VirusTotal"}

ABSENCE_NOTE = "Ne pas en conclure que c'est sain : un element recent ou rare n'est dans aucune base."


def _verdict(provider, status, headline, severity=None, code=None, advice=None, reference=None, details=None):
    """Assemble un verdict ; l'indicateur n'existe que pour les resultats inquietants."""
    indicator = None
    if severity and code:
        indicator = {"code": code, "severity": severity,
                     "reason": f"{TITLES[provider]} : {headline}"}
    return {"provider": provider, "title": TITLES[provider], "status": status, "headline": headline,
            "advice": advice, "reference": reference, "details": details or {}, "indicator": indicator}


def error_verdict(provider, message):
    """Verdict 'indisponible' (panne, cle refusee...)."""
    return _verdict(provider, "error", f"Interrogation impossible : {message}")


def skipped_verdict(provider, reason):
    """Verdict 'non interroge' (delai total depasse)."""
    return _verdict(provider, "unknown", reason)


def _unknown(provider, what, extra=""):
    """Verdict 'inconnu' : le service ne connait pas l'element (jamais synonyme de 'sain')."""
    return _verdict(provider, "unknown", f"{TITLES[provider]} ne connait pas {what}. {extra or ABSENCE_NOTE}")


def _day(text):
    """'2024-05-01 10:11:12 UTC' -> '2024-05-01' (la date suffit pour un humain)."""
    return str(text or "")[:10] or "date inconnue"


# --------------------------------------------------------------------------- MalwareBazaar
def malwarebazaar_hash(raw, sha256):
    """MalwareBazaar : present = malveillant (critique) ; absent = inconnu."""
    status = raw.get("query_status")
    if status == "ok" and raw.get("data"):
        d = raw["data"][0]
        family = d.get("signature") or "famille non precisee"
        tags = ", ".join((d.get("tags") or [])[:6])
        return _verdict(
            "malwarebazaar", "malicious",
            f"fichier connu comme malveillant : {family} ({d.get('file_type', '?')}), signale le {_day(d.get('first_seen'))}.",
            "critical", "ONLINE_MALWAREBAZAAR_KNOWN",
            advice="Ne pas ouvrir ce fichier. S'il a deja ete execute, deconnectez l'ordinateur du reseau et lancez une analyse antivirus complete.",
            reference=f"https://bazaar.abuse.ch/sample/{sha256}/",
            details={"famille": family, "type": d.get("file_type"), "etiquettes": tags,
                     "mode_de_diffusion": d.get("delivery_method")})
    if status in ("hash_not_found", "no_results"):
        return _unknown("malwarebazaar", "ce fichier")
    if status == "illegal_hash":
        return error_verdict("malwarebazaar", "empreinte invalide")
    return error_verdict("malwarebazaar", f"reponse inattendue ({status})")


# --------------------------------------------------------------------------- ThreatFox
def _confidence_severity(confidence):
    """Niveau de confiance ThreatFox (0-100) -> gravite."""
    if confidence >= 75:
        return "critical"
    return "high" if confidence >= 50 else "medium"


def _threatfox(raw, what, subject):
    """ThreatFox : gravite proportionnelle a la confiance du rapporteur."""
    status = raw.get("query_status")
    data = raw.get("data")
    if status == "ok" and isinstance(data, list) and data:
        confidence = max(int(d.get("confidence_level") or 0) for d in data)
        families = sorted({d.get("malware_printable") or d.get("malware") or "?" for d in data})
        kinds = sorted({d.get("threat_type", "?") for d in data})
        return _verdict(
            "threatfox", "malicious",
            f"{what} associe a {len(data)} indicateur(s) de compromission ({', '.join(families[:4])} ; "
            f"confiance {confidence} %, type : {', '.join(kinds[:3])}).",
            _confidence_severity(confidence), "ONLINE_THREATFOX_IOC",
            advice="Considerez cet element comme dangereux et ne vous y connectez pas.",
            reference=f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{subject}",
            details={"familles": families, "confiance": confidence, "indicateurs": len(data)})
    if status in ("no_result", "no_results") or (status == "ok" and not data):
        return _unknown("threatfox", "cet element")
    return error_verdict("threatfox", f"reponse inattendue ({status})")


def threatfox_hash(raw, sha256):
    """ThreatFox pour une empreinte de fichier."""
    return _threatfox(raw, "Fichier", sha256)


def threatfox_ioc(raw, term):
    """ThreatFox pour un lien, domaine ou adresse."""
    return _threatfox(raw, "Lien/serveur", term)


# --------------------------------------------------------------------------- URLhaus
def urlhaus_url(raw, url):
    """URLhaus pour un lien : en ligne = critique, hors ligne = eleve."""
    status = raw.get("query_status")
    if status == "ok":
        online = raw.get("url_status") == "online"
        threat = (raw.get("threat") or "malware").replace("_", " ")
        listed = [k for k, v in (raw.get("blacklists") or {}).items() if v and v != "not listed"]
        text = ("diffuse ACTUELLEMENT" if online else "a diffuse (aujourd'hui hors ligne)") + \
               f" un contenu dangereux ({threat}), signale le {_day(raw.get('date_added'))}."
        if listed:
            text += f" Egalement sur liste noire : {', '.join(listed)}."
        return _verdict("urlhaus", "malicious", "ce lien " + text,
                        "critical" if online else "high", "ONLINE_URLHAUS_MALICIOUS",
                        advice="N'ouvrez pas ce lien et ne telechargez rien depuis cette adresse.",
                        reference=raw.get("urlhaus_reference"),
                        details={"statut": raw.get("url_status"), "menace": threat,
                                 "etiquettes": raw.get("tags") or [], "fichiers": len(raw.get("payloads") or [])})
    if status == "no_results":
        return _unknown("urlhaus", "ce lien")
    if status in ("invalid_url", "missing_url"):
        return error_verdict("urlhaus", "lien invalide")
    return error_verdict("urlhaus", f"reponse inattendue ({status})")


def urlhaus_host(raw, host):
    """URLhaus pour un domaine : liens actifs = eleve, anciens = moyen."""
    status = raw.get("query_status")
    if status == "ok":
        n_online = int(raw.get("urls_online") or 0)
        total = len(raw.get("urls") or []) or int(raw.get("url_count") or 0)
        if n_online:
            return _verdict("urlhaus", "malicious",
                            f"le site {host} heberge ACTUELLEMENT {n_online} lien(s) dangereux ({total} signale(s) au total).",
                            "high", "ONLINE_URLHAUS_HOST", advice="Evitez ce site entierement.",
                            reference=raw.get("urlhaus_reference"), details={"actifs": n_online, "total": total})
        return _verdict("urlhaus", "suspicious",
                        f"le site {host} a deja heberge {total} lien(s) dangereux (aucun actif aujourd'hui).",
                        "medium", "ONLINE_URLHAUS_HOST", advice="Prudence : le site a ete compromis ou abuse par le passe.",
                        reference=raw.get("urlhaus_reference"), details={"actifs": 0, "total": total})
    if status in ("no_results",):
        return _unknown("urlhaus", f"le site {host}")
    return error_verdict("urlhaus", f"reponse inattendue ({status})")


def urlhaus_payload(raw, sha256):
    """URLhaus pour un fichier diffuse par des liens connus."""
    status = raw.get("query_status")
    if status == "ok":
        family = raw.get("signature") or "famille non precisee"
        return _verdict("urlhaus", "malicious",
                        f"ce fichier est un contenu dangereux diffuse par {raw.get('url_count', '?')} lien(s) "
                        f"({family}, {raw.get('file_type', '?')}).",
                        "critical", "ONLINE_URLHAUS_PAYLOAD",
                        advice="Ne pas ouvrir ce fichier.", reference=f"https://urlhaus.abuse.ch/browse.php?search={sha256}",
                        details={"famille": family, "liens": raw.get("url_count")})
    if status == "no_results":
        return _unknown("urlhaus", "ce fichier")
    return error_verdict("urlhaus", f"reponse inattendue ({status})")


# --------------------------------------------------------------------------- PhishTank
def _truthy(value):
    """Interprete les booleens renvoyes sous forme de texte ('true', 'yes', '1')."""
    return value is True or str(value).lower() in ("true", "yes", "1")


def phishtank(raw, url):
    """PhishTank : seul un hameconnage verifie ET actif est critique."""
    res = raw.get("results") or {}
    if not _truthy(res.get("in_database")):
        return _unknown("phishtank", "ce lien")
    ref = res.get("phish_detail_page")
    if _truthy(res.get("valid")) and _truthy(res.get("verified")):
        return _verdict("phishtank", "malicious", "hameconnage VERIFIE par la communaute et toujours actif.",
                        "critical", "ONLINE_PHISHTANK_PHISHING",
                        advice="Ne saisissez aucun mot de passe ni numero de carte. Fermez la page.", reference=ref,
                        details={"verifie": True, "actif": True})
    if _truthy(res.get("verified")):
        return _verdict("phishtank", "suspicious", "ancien hameconnage verifie, desormais desactive.",
                        "medium", "ONLINE_PHISHTANK_PHISHING", reference=ref,
                        advice="Le site n'est plus dangereux d'apres PhishTank, mais restez prudent.",
                        details={"verifie": True, "actif": False})
    return _verdict("phishtank", "suspicious", "signale comme hameconnage, verification en attente.",
                    "low", "ONLINE_PHISHTANK_PHISHING", reference=ref,
                    advice="Signalement non confirme : traitez le lien avec mefiance.", details={"verifie": False})


# --------------------------------------------------------------------------- VirusTotal
def _vt(raw, what, ref):
    """VirusTotal : 5 moteurs ou plus = malveillant (seuil EMBER2024) ; 1 a 4 = prudence ; 0 = rien trouve."""
    if raw.get("_http") == 404:
        return _unknown("virustotal", what, "Jamais analyse par VirusTotal : cela ne dit rien sur sa dangerosite.")
    attrs = (raw.get("data") or {}).get("attributes")
    if not attrs:
        return error_verdict("virustotal", "reponse inattendue")
    stats = attrs.get("last_analysis_stats") or {}
    mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    total = sum(int(stats.get(k, 0)) for k in ("malicious", "suspicious", "undetected", "harmless"))
    label = ((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")) or ""
    suffix = f" ({label})" if label else ""
    base = {"detections": mal, "suspects": sus, "moteurs": total}
    if mal >= 5:
        sev = "critical" if mal >= 10 else "high"
        return _verdict("virustotal", "malicious",
                        f"{mal} moteur(s) antivirus sur {total} detectent cet element{suffix}.", sev,
                        "ONLINE_VT_DETECTIONS", advice="Plusieurs antivirus independants sont d'accord : considerez-le dangereux.",
                        reference=ref, details=base)
    if mal >= 1:
        return _verdict("virustotal", "suspicious",
                        f"{mal} moteur(s) sur {total} le detectent{suffix}. Peu de detections : cela peut etre un faux positif.",
                        "medium" if mal >= 2 else "low", "ONLINE_VT_DETECTIONS",
                        advice="Verifiez l'origine de l'element avant de l'utiliser.", reference=ref, details=base)
    return _verdict("virustotal", "clean",
                    f"aucun des {total} moteurs antivirus ne le detecte. (Un element tres recent peut ne pas etre encore detecte.)",
                    reference=ref, details=base)


def virustotal_file(raw, sha256):
    """VirusTotal pour une empreinte de fichier."""
    return _vt(raw, "ce fichier", f"https://www.virustotal.com/gui/file/{sha256}")


def virustotal_url(raw, url):
    """VirusTotal pour un lien."""
    return _vt(raw, "ce lien", None)


# --------------------------------------------------------------------------- synthese
RANK = {"malicious": 4, "suspicious": 3, "error": 1, "unknown": 1, "clean": 2}


def summarize(verdicts):
    """Phrase de synthese + statut global (le pire resultat l'emporte)."""
    if not verdicts:
        return None
    worst = max(verdicts, key=lambda v: RANK.get(v["status"], 0))
    status = worst["status"]
    asked = len(verdicts)
    errors = sum(1 for v in verdicts if v["status"] == "error")
    if status == "malicious":
        who = ", ".join(sorted({v["title"] for v in verdicts if v["status"] == "malicious"}))
        text = f"Signale comme malveillant par : {who}."
    elif status == "suspicious":
        text = "Signalements partiels : verifiez avant d'utiliser cet element."
    elif status == "clean":
        text = "Aucun service consulte ne le signale. Ce n'est pas une garantie."
    else:
        text = "Aucun service consulte ne connait cet element. " + ABSENCE_NOTE
    if errors:
        text += f" ({errors}/{asked} service(s) injoignable(s) ou non configure(s).)"
    return {"status": status, "text": text}
