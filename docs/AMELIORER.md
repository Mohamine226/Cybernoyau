# Continuer à améliorer Mougle Protect

## Les gestes qui comptent le plus (par ordre d'effet)

1. **Ajouter vos programmes sains** et réentraîner EMBER (réduit les fausses alertes sur *votre* machine).
2. **Ajouter des malwares récents** (MalwareBazaar, theZoo, SOREL) : le modèle vieillit, les malwares évoluent.
3. **Donner des retours** (« C'est malveillant / C'est sûr ») : chaque erreur corrigée sert à l'entraînement.
4. **Activer les services en ligne** pour reconnaître les menaces très récentes.

## Recettes de développement

**Ajouter un détecteur** : dans `analysis/deep_analyzer.py`, produire un indicateur
`{"code": "MON_CODE", "severity": "medium", "reason": "phrase claire"}`. Ajouter son conseil dans
`alerts/recommendations.py` si besoin. Ajouter un test dans `tests/`.

**Ajouter une règle sans coder** : fichier JSON dans `data/rules/` (format dans `analysis/rules.py`).

**Ajouter un service en ligne** : 1) méthode de requête dans `intel/online/providers.py` ; 2) fonction
d'interprétation dans `interpret.py` (verdict + indicateur) ; 3) appel dans `manager.py` ; 4) entrée dans
`PROVIDERS`. Tester avec un faux transport (voir `tests/test_intel_online.py`).

**Ajouter un jeu de données** : dossier + README dans `data/datasets/`, entrée dans
`training/datasets.py::discover`, action dans `server/app.py::dataset_action`.

**Changer d'algorithme** : `training/ember_model.py::PROFILES` (hyperparamètres) ; l'interface et l'API ne
changent pas.

## Limites connues (à traiter si vous voulez aller plus loin)

- Analyse **statique** uniquement : pas d'exécution en bac à sable, donc pas de comportement observé.
- Un malware **inédit, chiffré ou chargé en mémoire** peut passer ; le modèle EMBER aide mais n'est pas parfait
  (sur le « challenge set » d'EMBER2024, les modèles de référence détectent mal les malwares évasifs).
- Les **sains de BODMAS** sont moins variés que ceux d'un vrai disque : mesurer le taux de fausses alertes sur
  vos propres fichiers sains avant de faire confiance aux alertes « élevées ».
- Pas de **protection en temps réel au niveau noyau** (pilote) : Mougle Protect observe et alerte.
- Android : analyse de liens / fichiers / APK seulement (Android interdit de surveiller les autres applications).
- **EMBER2024** (caractéristiques v3, format différent) non utilisé.
- Les adresses de `tools/fetch_feeds.py` et `tools/download_sorel.py` ne sont pas testées en réel.

## Pistes

- Extracteur EMBER v3 + second modèle (EMBER2024 : plus de formats, jeu « challenge »).
- Catégorie / famille probable (modèle multi-classes, `bodmas_malware_category.csv`).
- Bac à sable d'analyse dynamique (machine virtuelle jetable) pour observer le comportement.
- Détection des persistances Windows (clés Run, tâches planifiées, services) avec comparaison d'instantanés.
- Surveillance des connexions DNS ; pare-feu en mode « recommandation ».
- Signature des modèles et des listes échangés entre postes.
