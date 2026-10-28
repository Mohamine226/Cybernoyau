"""Renseignement sur les menaces : listes locales (hors ligne) et API externes (opt-in).

    store.py     tables SQLite : empreintes malveillantes/saines, liens, cache des API
    urls.py      normalisation des liens pour les comparer de facon fiable
    loaders.py   lecture des listes (TXT/CSV/GZ) et synchronisation du dossier data/threat_intel
    online/      clients des API externes + interpretation des reponses
"""
