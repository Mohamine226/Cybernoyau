# Mougle Protect — noyau Cubernoyau

Plateforme de cybersécurité locale : elle **surveille** votre ordinateur, **analyse** fichiers,
applications et liens, **explique** ce qu'elle trouve en phrases claires et **recommande** quoi faire.
Elle ne supprime, ne bloque et ne modifie rien toute seule.

> **Honnêteté d'abord.** Mougle Protect combine des règles, des listes de menaces connues et deux
> modèles d'apprentissage. C'est un bon deuxième regard, **pas un antivirus complet** : un malware
> inédit, chiffré ou chargé en mémoire peut passer. « Aucun indicateur » ne veut jamais dire « sûr ».
> Gardez un antivirus à jour.

## Démarrer

```bash
pip install -r requirements.txt
python main.py                 # http://127.0.0.1:8000
python main.py --lan           # + accès depuis un téléphone Android (code d'accès affiché)
python -m pytest               # 110+ tests, aucun ne touche le réseau
```

## Ce qu'il y a dans le projet

```
cubernoyau/            LE NOYAU (réutilisable sans le serveur)
  analysis/            analyse de fichiers, applications, APK, liens, comportements
  detection/           score de risque (noisy-OR) + moteur de décision
  features/            caractéristiques EMBER v2 (2381 valeurs) calculées avec pefile
  intel/               listes de menaces (hors ligne) + API externes (MalwareBazaar, ThreatFox,
                       URLhaus, PhishTank, VirusTotal) et interprétation de leurs réponses
  models/              modèles en service : Cubernoyau (tout fichier), EMBER (fichiers Windows),
                       Isolation Forest (processus)
  training/            jeux de données, entraînement EMBER chronologique, retours utilisateurs
  collectors/ storage/ alerts/ config/
server/                API FastAPI (app.py, scans.py, service.py)
frontend/              interface web (HTML/CSS/JS sans dépendance) + installation Android (PWA)
data/                  TOUTES les données — chaque jeu à sa place (voir ci-dessous)
tools/                 scripts en ligne de commande (entraîner, importer, ingérer, valider)
third_party/           code externe conservé tel quel (SOREL-20M, Apache-2.0)
docs/                  architecture, données, services en ligne, comment améliorer
tests/                 tests Python + test d'interface (tests/ui, jsdom)
```

## Où va chaque jeu de données

| Dossier | Contenu | Rangé par |
|---|---|---|
| `data/datasets/bodmas/` | `bodmas.npz`, `bodmas_metadata.csv`, `bodmas_malware_category.csv` | `tools/setup_datasets.py --bodmas …` |
| `data/datasets/sorel20m/` | `meta.db`, binaires désarmés téléchargés, exemples | `tools/setup_datasets.py --sorel …` |
| `data/datasets/thezoo/repo/` | clone de `ytisf/theZoo` | `git clone` (voir son README) |
| `data/datasets/custom/{malware,benign}/` | vos propres fichiers étiquetés | à la main |
| `data/threat_intel/hashes/{malware,benign}/` | listes d'empreintes SHA-256 (`.txt`, `.csv`, `.gz`) | automatique / `tools/import_bodmas.py` |
| `data/threat_intel/urls/{malware,phishing}/` | listes de liens (URLhaus, PhishTank, ThreatFox) | automatique |
| `data/models/ember/` | modèles EMBER entraînés (+ métriques JSON) | `tools/train_ember.py` ou l'interface |
| `data/rules/` | règles de détection personnalisées (`.json`) | à la main |

Chaque dossier contient un `README.md` qui dit quoi y mettre. Les gros fichiers ne sont pas versionnés (`.gitignore`).

## Les trois couches de détection

1. **Règles** (`analysis/`) : capacités offensives (injection, keylogger, persistance…), noms de familles
   de RAT, structure d'un exécutable (packers, imports absents), scripts, macros, PDF actifs, archives, APK.
2. **Connaissances** (`intel/`) : 57 000 empreintes de malwares et 77 000 de fichiers sains (BODMAS) déjà
   incluses, plus toute liste que vous ajoutez ; en option, les services en ligne (désactivés par défaut,
   n'envoient que des empreintes ou des liens, **jamais un fichier**).
3. **Apprentissage** (`models/`, `training/`) : modèle EMBER entraîné sur BODMAS (AUC 0,9999 sur les fichiers
   les plus récents du jeu, seuils mesurés) + modèle Cubernoyau qui apprend de vos fichiers et de vos retours.

Tout est combiné en un **score** explicable (`detection/risk_scorer.py`) : chaque niveau est toujours
accompagné de ses raisons.

## Continuer à l'améliorer

Voir [`docs/AMELIORER.md`](docs/AMELIORER.md) : ajouter des données, un détecteur, un service en ligne,
un jeu de données ; limites connues et pistes classées par intérêt.

## Licences et sources

Voir [`docs/LICENCES.md`](docs/LICENCES.md) — **à lire avant toute diffusion** (EMBER est sous AGPL-3.0).
