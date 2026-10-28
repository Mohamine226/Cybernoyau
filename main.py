"""Point d'entree de Mougle Protect (noyau Cubernoyau).

    python main.py          -> http://127.0.0.1:8000  (cet ordinateur seulement)
    python main.py --lan    -> accessible depuis un telephone Android du meme Wi-Fi,
                               protege par un code d'acces affiche au demarrage.

Au demarrage, le serveur lance la surveillance continue et importe en arriere-plan les
listes de data/threat_intel/. Aucune variable d'environnement n'est obligatoire ; voir
cubernoyau/config/settings.py pour la liste de celles qui existent.
"""

import argparse
import os
import secrets
import socket


def lan_ip():
    """Adresse de cet ordinateur sur le reseau local (aucun paquet n'est reellement envoye)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("10.255.255.255", 1))     # adresse non routee : sert seulement a choisir l'interface
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


def main():
    parser = argparse.ArgumentParser(description="Mougle Protect (Cubernoyau)")
    parser.add_argument("--lan", action="store_true",
                        help="autoriser l'acces depuis le reseau local (jeton obligatoire)")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    host = "127.0.0.1"                           # par defaut : jamais expose au reseau
    if args.lan:
        host = "0.0.0.0"
        # Sans jeton, n'importe qui sur le Wi-Fi pourrait piloter l'application : on en impose un.
        if not os.environ.get("CUBERNOYAU_TOKEN"):
            os.environ["CUBERNOYAU_TOKEN"] = secrets.token_urlsafe(9)
        token = os.environ["CUBERNOYAU_TOKEN"]
        print("\nMougle Protect - acces telephone (meme Wi-Fi) :")
        print(f"  http://{lan_ip()}:{args.port}/?token={token}")
        print("  Le trafic local n'est pas chiffre : a utiliser sur un reseau de confiance.\n")
    else:
        print(f"\nMougle Protect : http://127.0.0.1:{args.port}\n")

    import uvicorn                               # import tardif : demarrage plus rapide de --help
    uvicorn.run("server.app:app", host=host, port=args.port)


if __name__ == "__main__":
    main()
