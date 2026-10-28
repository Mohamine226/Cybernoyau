"""Actions recommandees. Aucune action n'est appliquee automatiquement."""

from cubernoyau.detection.risk_scorer import LEVEL_HIGH, LEVEL_NONE, LEVEL_SUSPECT

_COMMON_NOTE = "Cubernoyau n'a supprime, bloque ni modifie aucun element."

RECOMMENDATIONS = {
    "file": {
        LEVEL_SUSPECT: [
            "Ne pas ouvrir le fichier tant que son origine n'est pas confirmee.",
            "Verifier l'empreinte SHA-256 sur un service de reputation (ex. VirusTotal).",
            "Demander a l'expediteur de confirmer l'envoi par un autre canal.",
        ],
        LEVEL_HIGH: [
            "Ne pas ouvrir ni executer le fichier.",
            "Le deplacer hors des dossiers courants ou le mettre en quarantaine avec l'antivirus.",
            "Verifier l'empreinte SHA-256 sur un service de reputation et lancer une analyse antivirus complete.",
        ],
    },
    "application": {
        LEVEL_SUSPECT: [
            "Verifier l'origine de l'application (site officiel de l'editeur).",
            "Comparer la signature numerique et l'editeur affiches.",
            "Ne pas l'executer si l'origine est inconnue.",
        ],
        LEVEL_HIGH: [
            "Ne pas executer l'application ; si elle tourne, la fermer depuis le gestionnaire de taches apres verification.",
            "Lancer une analyse antivirus complete.",
            "Changer les mots de passe importants si l'application a deja ete executee.",
        ],
    },
    "link": {
        LEVEL_SUSPECT: [
            "Ne pas saisir d'identifiants ou d'informations bancaires sur ce lien.",
            "Acceder au service en tapant l'adresse officielle vous-meme.",
        ],
        LEVEL_HIGH: [
            "Ne pas ouvrir ce lien.",
            "Si vous l'avez deja ouvert et saisi un mot de passe, le changer immediatement et activer la double authentification.",
            "Signaler le message (phishing) au service concerne.",
        ],
    },
    "process": {
        LEVEL_SUSPECT: [
            "Verifier le chemin, la signature et le processus parent dans le gestionnaire de taches.",
            "Ne pas arreter un processus systeme sur la seule base de cette alerte.",
        ],
        LEVEL_HIGH: [
            "Verifier immediatement l'origine du processus et son executable.",
            "Deconnecter temporairement le PC du reseau si un comportement malveillant est confirme.",
            "Lancer une analyse antivirus complete.",
        ],
    },
    "network": {
        LEVEL_SUSPECT: [
            "Identifier le processus et la destination dans le moniteur de ressources.",
            "Verifier si cette connexion correspond a une application que vous utilisez.",
        ],
        LEVEL_HIGH: [
            "Deconnecter temporairement le PC du reseau et verifier le processus concerne.",
            "Lancer une analyse antivirus complete.",
        ],
    },
    "file_activity": {
        LEVEL_SUSPECT: [
            "Verifier quelle application modifie ou supprime ces fichiers.",
            "Verifier que vos sauvegardes sont a jour.",
        ],
        LEVEL_HIGH: [
            "Possible chiffrement massif : deconnecter le PC du reseau et couper l'activite suspecte sans eteindre brutalement si possible.",
            "Ne payer aucune rancon ; verifier les sauvegardes hors ligne.",
            "Contacter un responsable securite ou un professionnel.",
        ],
    },
}

DEFAULT = {
    LEVEL_SUSPECT: ["Verifier l'element avec prudence avant toute action."],
    LEVEL_HIGH: ["Ne pas utiliser l'element et le faire verifier."],
}


def recommend(source, level):
    """Gestes recommandes selon la source (fichier, lien, processus...) et le niveau de risque."""
    if level == LEVEL_NONE:
        return [
            "Aucun indicateur detecte, ce qui ne garantit pas que l'element "
            "est sur : rester prudent sur son origine."
        ]
    table = RECOMMENDATIONS.get(source, DEFAULT)
    return list(table.get(level, DEFAULT[level])) + [_COMMON_NOTE]
