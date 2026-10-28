"""API externes d'analyse (OPTIONNELLES, desactivees par defaut).

    base.py        client HTTP (delai, identification, transport remplacable pour les tests)
    providers.py   un client par service : MalwareBazaar, ThreatFox, URLhaus, PhishTank, VirusTotal
    interpret.py   traduction des reponses brutes en verdicts lisibles + indicateurs de risque
    manager.py     facade : reglages, cles, cache, interrogation de tous les services actives

CONFIDENTIALITE : seules des empreintes SHA-256, des liens ou des noms de domaine sont
envoyes. JAMAIS le contenu d'un fichier. Chaque service est active separement.
"""
