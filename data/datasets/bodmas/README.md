# BODMAS (Blue Hexagon Open Dataset for Malware Analysis)
**Place ici** les 3 fichiers du jeu :
- `bodmas.npz`  : `X` (134 435 x 2381, caracteristiques EMBER v2) et `y` (0 = sain, 1 = malveillant)
- `bodmas_metadata.csv` : `sha256, timestamp, family` (meme ordre que `X`)
- `bodmas_malware_category.csv` : `sha256, category`

Ou lance `python tools/setup_datasets.py --bodmas <dossier-ou-zip>` pour les ranger.
Utilise par : `python tools/train_ember.py` (entrainement du modele EMBER) et par
`python tools/import_bodmas.py` (empreintes -> base de hachages connus).
Les fichiers `.npz`/`.csv` sont volumineux : ils ne sont pas versionnes (voir `.gitignore`).
