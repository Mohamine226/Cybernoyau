
from pathlib import Path


# Extensions qui méritent une attention particulière.
# Elles ne sont pas malveillantes par nature.
RISKY_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd",
    ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".hta", ".msi", ".reg", ".lnk"
}

# Noms fréquemment associés à des composants Windows.
# Leur présence ailleurs que dans un emplacement attendu
# constitue un indicateur à vérifier, pas une preuve.
WINDOWS_LIKE_NAMES = {
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "services.exe",
    "smss.exe",
    "spoolsv.exe",
    "explorer.exe",
}


def detect_double_extension(file_name):
    """Repere certains noms de fichiers a double extension."""
    path = Path(file_name)
    suffixes = [suffix.lower() for suffix in path.suffixes]

    if len(suffixes) < 2:
        return False

    # Exemples : facture.pdf.exe, photo.jpg.scr
    return (
        suffixes[-1] in RISKY_EXTENSIONS
        and any(
            suffix in {
                ".pdf", ".jpg", ".jpeg", ".png", ".doc",
                ".docx", ".xls", ".xlsx", ".txt", ".zip"
            }
            for suffix in suffixes[:-1]
        )
    )


def detect_file_risks(file_info):
    """
    Produit des indicateurs explicables a partir des metadonnees.
    Ne declare jamais un fichier malveillant sur ces seuls criteres.
    """
    indicators = []

    name = file_info.get("file_name", "")
    extension = file_info.get("extension", "").lower()
    file_path = file_info.get("file_path", "")
    signature = file_info.get("digital_signature", {})
    signature_status = signature.get("status", "unknown")

    path = Path(file_path)
    normalized_path = str(path).lower()

    # 1. Extension potentiellement executable.
    if extension in RISKY_EXTENSIONS:
        indicators.append({
            "code": "EXECUTABLE_OR_SCRIPT_EXTENSION",
            "severity": "info",
            "reason": (
                "Le fichier possede une extension executable "
                "ou associee a un script."
            )
        })

    # 2. Double extension trompeuse.
    if detect_double_extension(name):
        indicators.append({
            "code": "MISLEADING_DOUBLE_EXTENSION",
            "severity": "medium",
            "reason": (
                "Le nom associe une extension de document ou d'image "
                "a une extension executable ou script."
            )
        })

    # 3. Nom ressemblant a un composant Windows dans un emplacement
    # inhabituel. Les fichiers systeme peuvent legitiment se trouver
    # ailleurs dans certains contextes : une verification humaine reste
    # necessaire.
    if name.lower() in WINDOWS_LIKE_NAMES:
        expected_prefixes = (
            str(Path("C:/Windows/System32")).lower(),
            str(Path("C:/Windows/SysWOW64")).lower(),
            str(Path("C:/Windows/WinSxS")).lower(),
        )

        if not normalized_path.startswith(expected_prefixes):
            indicators.append({
                "code": "WINDOWS_LIKE_NAME_UNUSUAL_LOCATION",
                "severity": "medium",
                "reason": (
                    "Le nom ressemble a celui d'un composant Windows, "
                    "mais le fichier n'est pas dans un emplacement "
                    "systeme Windows habituel."
                )
            })

    # 4. Signature invalide. L'absence de signature n'est pas
    # consideree automatiquement comme suspecte.
    if signature_status in {"HashMismatch", "NotTrusted"}:
        indicators.append({
            "code": "SIGNATURE_REQUIRES_REVIEW",
            "severity": "high",
            "reason": (
                "Le controle de signature retourne un statut qui "
                "necessite une verification approfondie."
            )
        })

    # 5. Signaler une erreur de controle sans conclure a une infection.
    if signature_status == "error":
        indicators.append({
            "code": "SIGNATURE_CHECK_ERROR",
            "severity": "info",
            "reason": (
                "Le controle de signature a echoue. Le resultat "
                "est inconnu et doit etre verifie."
            )
        })

    return {
        "file_name": name,
        "risk_indicators_count": len(indicators),
        "indicators": indicators,
        "assessment": (
            "A_VERIFIER" if indicators else "AUCUN_INDICATEUR_DETECTE"
        ),
        "notice": (
            "Ces indicateurs ne prouvent pas qu'un fichier est "
            "malveillant. Le contexte et une analyse complementaire "
            "sont necessaires."
        )
    }
