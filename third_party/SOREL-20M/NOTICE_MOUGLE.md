# SOREL-20M (code de reference)

Copie **inchangee** du depot https://github.com/sophos/SOREL-20M (Sophos / ReversingLabs),
sous licence Apache-2.0 (voir `LICENSE.md`). Les conditions d'utilisation des *donnees*
(`Terms and Conditions of Use.pdf`) s'appliquent des que vous telechargez le jeu depuis S3.

Ce que Mougle Protect en reprend :
- les **hyperparametres LightGBM de reference** (`lightgbm_config.json`) -> profil
  d'entrainement `standard` de `cubernoyau/training/ember_model.py` ;
- les **dates de decoupage temporel** (`config.py`) -> principe train / validation / test
  chronologiques (pour mesurer la derive des malwares, pas un melange aleatoire) ;
- le **schema des donnees** (`dataset.py`, README) -> `tools/import_sorel_meta.py`,
  `tools/download_sorel.py`.
Le reseau de neurones (`nets.py`, `train.py`) est conserve ici comme point de depart si vous
voulez ajouter un second modele (necessite PyTorch, non installe par defaut).
