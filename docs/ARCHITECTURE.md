# Architecture

## Vue d'ensemble

```
 navigateur / téléphone ──► server/app.py (FastAPI) ──► server/service.py  (surveillance en continu)
                                      │                 server/scans.py    (analyses à la demande)
                                      ▼
                       ┌───────────── cubernoyau (noyau) ──────────────┐
  fichier / lien ──►   │ analysis → intel → models → detection → alerts │ ──► alerte + recommandations
                       └──────────────── storage (SQLite) ──────────────┘
```

Le **noyau** (`cubernoyau/`) ne dépend pas du serveur : on peut l'utiliser depuis un script ou une
autre interface. Le **serveur** assemble les briques ; l'**interface** n'est qu'un client de l'API.

## Le trajet d'un fichier analysé (`server/scans.py::_analyze`)

1. **Analyse locale** (`analysis/file_analyzer`, `application_analyzer`, `apk_analyzer`) : nom, double
   extension, emplacement, signature, permissions Android…
2. **Moteur profond** (`analysis/deep_analyzer`) : lecture en flux (toute taille), type réel, entropie, motifs,
   structure PE, capacités offensives, règles, empreinte connue, modèle Cubernoyau.
3. **Listes locales** (`intel/store`) : fichier sain connu (information seulement).
4. **Modèle EMBER** (`models/ember_classifier`, fichiers Windows) : probabilité + gravité d'après des seuils mesurés.
5. **Services en ligne** (`intel/online`, facultatif) : verdicts interprétés (voir `SERVICES_EN_LIGNE.md`).
6. **Score** (`detection/risk_scorer`) puis **décision** (`detection/decision_engine`) puis **alerte**
   (`alerts/alert_manager`, avec délai anti-spam).

Tout au long, chaque constat est un **indicateur** `{code, severity, reason}`. Ajouter une détection =
produire un indicateur ; le score et l'interface le prennent en charge sans autre changement.

## La surveillance (`server/service.py::run_cycle`)

Toutes les `MONITOR_INTERVAL` secondes : collecte des processus → règles de comportement → Isolation Forest →
analyse profonde des **nouveaux** exécutables → connexions réseau → corrélation (un programme venu d'un dossier
utilisateur + qui contacte l'extérieur + dont l'analyse statique est suspecte = signal fort) → activité des
fichiers (modifications massives) → alertes.

## Données

Tout vit dans `data/` (déplaçable : `CUBERNOYAU_DATA`). La base SQLite `data/cubernoyau.db` contient alertes,
historique, empreintes/liens connus, vecteurs d'entraînement, cache des services en ligne et réglages.
Les modèles EMBER sont des fichiers texte (sans pickle) dans `data/models/ember/`.

## Conventions

- **Jamais d'exécution** : aucun fichier analysé n'est lancé ; un fichier téléversé est supprimé après analyse.
- **Jamais de verdict absolu** : « aucun indicateur » ≠ « sain », et chaque niveau est expliqué.
- **Aucune action automatique** sur l'ordinateur de l'utilisateur.
- **Réseau = option** : tout fonctionne hors ligne ; les services externes sont désactivés par défaut.
- Messages de l'interface et commentaires en français.
