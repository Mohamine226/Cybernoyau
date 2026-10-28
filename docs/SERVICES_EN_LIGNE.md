# Services en ligne (API externes d'analyse)

Désactivés par défaut. Activation : page **Services en ligne** (interrupteur général, un par service, clés).
Hors ligne, tout le reste fonctionne.

## Confidentialité

Envoyé : l'**empreinte SHA-256** d'un fichier, un **lien** ou un **nom de domaine**. **Jamais** le contenu d'un
fichier. L'interface indique, pour chaque service, exactement ce qu'il reçoit. Les clés ne sont jamais
renvoyées par l'API (seulement les 4 derniers caractères) ; elles peuvent aussi venir de variables
d'environnement (`CUBERNOYAU_ABUSECH_KEY`, `CUBERNOYAU_PHISHTANK_KEY`, `CUBERNOYAU_VT_KEY`).

## Les services

| Service | Question posée | Clé |
|---|---|---|
| MalwareBazaar | ce fichier (SHA-256) est-il un malware connu ? | abuse.ch (gratuite) |
| ThreatFox | ce fichier / lien / domaine est-il lié à un indicateur de compromission ? | abuse.ch |
| URLhaus | ce lien (ou domaine, ou fichier) diffuse-t-il des malwares ? | abuse.ch |
| PhishTank | ce lien est-il un hameçonnage vérifié ? | facultative |
| VirusTotal | combien d'antivirus détectent ce fichier / lien ? | VirusTotal |

## Comment les réponses sont interprétées (`intel/online/interpret.py`)

- **« Inconnu » n'est jamais « sain »** : un élément récent ou rare n'est dans aucune base.
- MalwareBazaar ne contient que des malwares : présent ⇒ **critique**.
- ThreatFox : gravité selon la confiance du rapporteur (≥ 75 critique, ≥ 50 élevée, sinon moyenne).
- URLhaus : lien **en ligne** ⇒ critique ; **hors ligne** ⇒ élevé ; domaine avec liens actifs ⇒ élevé, anciens ⇒ moyen.
- PhishTank : seul « vérifié **et** actif » est critique ; ancien/inactif ⇒ moyen ; non vérifié ⇒ faible.
- VirusTotal : ≥ 10 moteurs critique, ≥ 5 élevé (seuil du jeu EMBER2024), 2-4 moyen, 1 faible, 0 « rien trouvé ».

Chaque verdict devient un indicateur (`ONLINE_*`) combiné avec le reste par le score de risque.

## Garde-fous

Cache de 24 h (`CUBERNOYAU_ONLINE_CACHE_HOURS`) — pas de requête inutile, quotas respectés ; erreurs jamais
mises en cache ; une panne n'empêche jamais l'analyse (verdict « indisponible ») ; budget de temps total par lot
de liens. Respectez les conditions d'utilisation (abuse.ch : usage équitable, usage commercial = abonnement).

## État de validation

Les clients, l'interprétation, le cache et les erreurs sont testés **sans réseau** avec des réponses de la forme
documentée (`tests/test_intel_online.py`). **Non testés contre les serveurs réels** (réseau fermé pendant le
développement) : ajoutez votre clé, utilisez le bouton « Tester » de chaque service, et signalez toute différence
de format — seul `providers.py` et `interpret.py` sont concernés.
