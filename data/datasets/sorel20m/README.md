# SOREL-20M (Sophos / ReversingLabs)
Le depot GitHub fourni contient seulement le **code** (copie dans `third_party/SOREL-20M/`).
Les **donnees** (~8 To) sont sur S3 public : ne telecharge que ce qu'il te faut.
- `meta.db` (3,5 Go) : index + etiquettes (sha256, is_malware...) -> `python tools/import_sorel_meta.py meta.db`
- `binaries/` : echantillons *desarmes* (zlib) -> `python tools/download_sorel.py --count 500 --label malware`
- `shas_missing_ember_features.json` : empreintes sans caracteristiques EMBER (liste d'exclusion)
Les conditions d'utilisation de SOREL s'appliquent (voir `third_party/SOREL-20M`).
