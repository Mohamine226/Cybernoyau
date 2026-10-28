"""Moteur de decision : transforme un niveau de risque en reponse a l'utilisateur.

Principe de conception : Mougle Protect OBSERVE, EXPLIQUE et RECOMMANDE ; il n'agit
jamais seul (`automatic_action` vaut toujours "aucune"). Supprimer ou bloquer a la
place de l'utilisateur sur la base d'une analyse statique provoquerait tot ou tard
un faux positif destructeur ; on laisse donc la decision a la personne.
"""

from cubernoyau.alerts.recommendations import recommend
from cubernoyau.detection.risk_scorer import LEVEL_HIGH, LEVEL_NONE


def decide(source, risk):
    """Reponse de Cubernoyau : alerter, expliquer, proposer, enregistrer.

    source : "file", "application", "link", "process"... (choisit les conseils adaptes).
    risk   : resultat de `score_indicators`.
    """
    level = risk["level"]
    return {
        "level": level,
        "alert": level != LEVEL_NONE,            # une alerte est levee des "suspect"
        "urgent": level == LEVEL_HIGH,           # "urgent" : a traiter en priorite
        "explanation": risk.get("main_reasons", []),
        "recommended_actions": recommend(source, level),
        "automatic_action": "aucune",            # voir l'en-tete du module
        "report_saved": True,
    }
