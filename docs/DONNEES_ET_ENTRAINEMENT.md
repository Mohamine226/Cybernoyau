# Données et entraînement

## Les deux modèles

| | EMBER | Cubernoyau |
|---|---|---|
| Fichiers visés | programmes Windows (PE) | tous les types |
| Caractéristiques | 2381 valeurs standard EMBER v2 (`features/ember_v2.py`) | ~38 valeurs maison (`analysis/deep_analyzer.py`) |
| Algorithme | LightGBM (arbres de décision boostés) | RandomForest |
| Données de base | **BODMAS** (134 435 fichiers) + vos fichiers | vos fichiers et retours |
| Où | `training/ember_model.py`, `models/ember_classifier.py` | `training/service.py`, `models/file_classifier.py` |

## Entraîner EMBER

```bash
python tools/setup_datasets.py --bodmas "dataset de bodmas.zip"    # range les fichiers
python tools/train_ember.py                                       # ~2 min sur 1 cœur (profil rapide)
python tools/train_ember.py --profile standard                    # hyperparamètres SOREL-20M
```
ou le bouton **Données et entraînement → Modèle pour Windows** de l'interface.

**Découpage chronologique** (comme SOREL-20M / EMBER2024) : 75 % les plus anciens pour apprendre, 10 % pour
régler l'arrêt et **calculer les seuils**, 15 % les plus récents pour mesurer. On juge ainsi le modèle sur des
fichiers *plus récents* que ceux appris, ce qui reflète la vraie vie (les malwares évoluent).

**Seuils d'alerte mesurés** : « élevé » = score au-dessus duquel seuls 0,1 % des fichiers sains de validation
passent ; « moyen » = 1 % ; « faible » = 5 %. Résultat du modèle livré : AUC 0,9999, 99,6 % des malwares récents
détectés à ~0,2 % de fausses alertes.

**Lire ces chiffres avec prudence** : BODMAS contient 43 % de malwares ; sur un ordinateur normal, presque tout
est sain, donc un même taux d'erreur produit relativement plus de fausses alertes. Les sains de BODMAS sont aussi
moins variés que ceux de votre disque. **Ajoutez vos propres programmes sains** (`data/datasets/custom/benign/`
ou `tools/ingest_folder.py --label benign`) puis réentraînez : c'est le geste qui améliore le plus la fiabilité.

## Apporter de nouvelles données

| Source | Commande | Effet |
|---|---|---|
| Dossier de fichiers étiquetés | `tools/ingest_folder.py --label malware\|benign DOSSIER` | vecteurs EMBER + caractéristiques Cubernoyau + empreintes |
| theZoo (archives, mot de passe `infected`) | `tools/ingest_thezoo.py` | idem, sans jamais exécuter ni conserver les fichiers |
| SOREL-20M (étiquettes) | `tools/import_sorel_meta.py meta.db` | des millions d'empreintes malveillantes |
| SOREL-20M (échantillons) | `tools/download_sorel.py meta.db --count 500` | binaires désarmés à ingérer |
| Listes d'empreintes / de liens | déposer dans `data/threat_intel/…` ou page *Menaces connues* | reconnaissance instantanée hors ligne |
| Flux publics | `tools/fetch_feeds.py --abusech-key …` | MalwareBazaar, URLhaus, ThreatFox, PhishTank |
| Retours utilisateurs | boutons « C'est malveillant / C'est sûr » | alimentent les deux modèles |
| Jeu d'un autre poste | export / import CSV | partage de **nombres**, jamais de fichiers ni de modèles |

Les empreintes seules alimentent la reconnaissance des malwares **connus** ; l'apprentissage a besoin des
fichiers (ou de vecteurs).

## Entraînement automatique

Les retours « malveillant / sûr » s'accumulent. Dès `AUTO_TRAIN_MIN_NEW` (20) nouveaux échantillons le modèle
Cubernoyau se réentraîne ; EMBER se réentraîne après cinq fois plus de nouveaux vecteurs (plus long). Réglable
dans l'interface. Un nouveau modèle n'est activé que s'il n'est pas moins bon que l'actuel ; on peut revenir en
arrière depuis la liste des modèles.

## Sécurité des modèles

Les modèles EMBER sont enregistrés en **texte** (LightGBM) : pas de pickle, donc pas d'exécution de code au
chargement ; on peut les échanger. Le modèle Cubernoyau utilise joblib (pickle) : ne chargez jamais un
`.joblib` venu d'une source inconnue ; échangez plutôt des jeux CSV de caractéristiques.

## Validation de l'extracteur EMBER

`features/ember_v2.py` est une réécriture avec pefile. `tools/validate_ember_features.py` la compare au code
officiel (téléchargé à la volée) : sur 8 vrais exécutables (x86, x64, ARM64), **2380 valeurs sur 2381
identiques** ; l'écart connu (`has_relocations`) vient de LIEF récent qui ne lit plus les relocations alors que
BODMAS (LIEF 0.9) les lisait : notre extracteur suit la définition d'origine (61 % des sains de BODMAS en ont).
