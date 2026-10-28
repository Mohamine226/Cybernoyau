"""Fusion des indicateurs en un score de risque explicable (0 a 100).

Pourquoi pas une simple addition ? Parce que dix petits signaux faibles ne valent pas
un signal fort, et parce que plusieurs indicateurs qui disent la meme chose ne doivent
pas compter plusieurs fois. On utilise donc la methode « noisy-OR » :

    chaque indicateur a une "probabilite d'etre significatif" (son poids, selon sa gravite) ;
    le score est la probabilite qu'AU MOINS UN indicateur soit significatif :

        score = 1 - (1 - p1) x (1 - p2) x ... x (1 - pn)

Exemples (poids ci-dessous) :
    un indicateur "moyen" seul                 -> 25  => a verifier
    un "eleve" seul                            -> 50  => risque eleve
    "moyen" + "moyen"                          -> 44  => a verifier (presque eleve)
    "moyen" + "moyen" + "faible"               -> 47  => a verifier
    un "critique" (ex. empreinte connue)       -> 95  => risque eleve
    quinze indicateurs "info" (poids 0,02)     -> 26  => a verifier ; un seul -> 2 => aucun

Deux indicateurs de meme code ne comptent qu'une fois (voir `score_indicators`).
Le score N'EST PAS une probabilite de malveillance : c'est un indice de priorite,
toujours accompagne des raisons qui l'expliquent.
"""

# Poids de chaque gravite. "critical" est reserve aux preuves directes : empreinte deja
# connue comme malveillante, fichier signale par plusieurs antivirus, lien actif d'un malware.
SEVERITY_WEIGHT = {"info": 0.02, "low": 0.06, "medium": 0.25, "high": 0.5,
                   "critical": 0.95}

LEVEL_NONE = "AUCUN_INDICATEUR_DETECTE"   # volontairement PAS "sain" : on ne peut pas le prouver
LEVEL_SUSPECT = "SUSPECT"
LEVEL_HIGH = "RISQUE_ELEVE"
LEVELS = [LEVEL_NONE, LEVEL_SUSPECT, LEVEL_HIGH]   # du moins grave au plus grave

# Seuils : en dessous de 10, le bruit de fond d'indicateurs "info" ne declenche rien ;
# a partir de 50, un seul indicateur "eleve" suffit (c'est voulu : il est precis).
SUSPECT_THRESHOLD = 10.0
HIGH_THRESHOLD = 50.0

LIMITATIONS = (
    "Analyse statique et heuristique : un resultat 'aucun indicateur' ne "
    "prouve pas qu'un element est sur, et un indicateur ne prouve pas "
    "qu'il est malveillant."
)


def level_for_score(score):
    """Niveau de risque d'un score 0-100 (aucun / suspect / eleve)."""
    if score >= HIGH_THRESHOLD:
        return LEVEL_HIGH
    if score >= SUSPECT_THRESHOLD:
        return LEVEL_SUSPECT
    return LEVEL_NONE


def score_indicators(indicators):
    """Fusionne une liste d'indicateurs {code, severity, reason} en un verdict.

    Retourne {score 0-100, level, indicators_count, main_reasons, limitations}.
    `main_reasons` = les trois raisons les plus graves, en phrases : c'est ce qui rend
    le score explicable (on ne montre jamais un niveau sans dire pourquoi).
    """
    remaining = 1.0          # probabilite qu'AUCUN indicateur ne soit significatif
    seen = set()             # codes deja comptes : un meme code ne s'additionne pas
    unique = []

    for indicator in indicators or []:
        code = indicator.get("code")
        if code in seen:
            continue
        seen.add(code)
        unique.append(indicator)
        # Une gravite inconnue vaut 0 : elle ne peut jamais faire monter le score par erreur.
        remaining *= 1.0 - SEVERITY_WEIGHT.get(indicator.get("severity"), 0.0)

    score = round((1.0 - remaining) * 100, 1)
    # Raisons classees de la plus grave a la moins grave.
    ranked = sorted(
        unique,
        key=lambda i: SEVERITY_WEIGHT.get(i.get("severity"), 0.0),
        reverse=True,
    )

    return {
        "score": score,
        "level": level_for_score(score),
        "indicators_count": len(unique),
        "main_reasons": [i.get("reason", i.get("code")) for i in ranked[:3]],
        "limitations": LIMITATIONS,
    }


def max_level(*levels):
    """Le plus grave de plusieurs niveaux (ex. le pire fichier d'un dossier)."""
    return max(levels, key=LEVELS.index)
