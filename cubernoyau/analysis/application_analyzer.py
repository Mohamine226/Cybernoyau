"""Cubernoyau - Analyse statique d'applications.

Examine un executable (ou les executables des processus collectes) sans
jamais l'executer : empreinte, signature, emplacement, en-tete PE,
entropie. Les indicateurs sont des observations a verifier.
"""

import argparse
import json
import math
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from cubernoyau.analysis.file_analyzer import analyze_file, save_report

from cubernoyau.config.settings import BASE_DIR, DATA_DIR  # noqa: E402,F401
RAW_DIR = DATA_DIR / "runtime" / "raw"

APP_EXTENSIONS = {".exe", ".dll", ".scr", ".msi", ".com", ".sys"}

# Dossiers ecrits par l'utilisateur : les applications legitimes s'y
# trouvent parfois (Teams, Discord...), donc indicateur de faible poids.
USER_WRITABLE_MARKERS = (
    "\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\downloads\\",
    "\\users\\public\\", "\\windows\\temp\\", "\\programdata\\",
    "/tmp/", "/downloads/",
)

ENTROPY_THRESHOLD = 7.2  # proche du maximum (8) : contenu compresse/chiffre


def shannon_entropy(data):
    """Entropie de Shannon (0..8) d'une suite d'octets."""
    if not data:
        return 0.0
    total = len(data)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in Counter(data).values()
    )


def read_pe_info(path, sample_size=4 * 1024 * 1024):
    """Lit l'en-tete PE et l'entropie, sans executer le fichier."""
    info = {"is_pe": False, "entropy": None, "sample_bytes": 0}
    with path.open("rb") as file:
        head = file.read(sample_size)

    info["sample_bytes"] = len(head)
    info["entropy"] = round(shannon_entropy(head), 3)

    if head[:2] == b"MZ" and len(head) >= 64:
        offset = int.from_bytes(head[0x3C:0x40], "little")
        if 0 < offset < len(head) - 4 and head[offset:offset + 4] == b"PE\0\0":
            info["is_pe"] = True
    return info


def detect_application_risks(file_result, pe_info):
    """Indicateurs propres aux applications : emplacement, extension, signature, entropie."""
    indicators = []
    ext = file_result.get("extension", "")
    path = file_result.get("file_path", "").lower()
    signature = file_result.get("digital_signature", {}).get("status")

    def add(code, severity, reason):
        indicators.append(
            {"code": code, "severity": severity, "reason": reason})

    if ext in {".exe", ".dll", ".scr", ".sys"} and not pe_info["is_pe"]:
        if pe_info["sample_bytes"] > 0:
            add("EXTENSION_HEADER_MISMATCH", "medium",
                "L'extension annonce un programme Windows mais "
                "l'en-tete PE est absent ou invalide.")

    if pe_info["is_pe"] and ext not in APP_EXTENSIONS:
        add("PE_WITH_NON_EXECUTABLE_EXTENSION", "high",
            "Le contenu est un programme Windows mais l'extension "
            "ne l'indique pas.")

    if any(marker in path for marker in USER_WRITABLE_MARKERS):
        add("USER_WRITABLE_LOCATION", "low",
            "Application situee dans un dossier modifiable par "
            "l'utilisateur (temporaire, telechargements, AppData).")

    if (pe_info["entropy"] or 0) >= ENTROPY_THRESHOLD and pe_info["is_pe"]:
        add("HIGH_ENTROPY", "low",
            f"Entropie elevee ({pe_info['entropy']}/8) : contenu "
            "possiblement compresse ou protege. Courant aussi pour "
            "des installateurs legitimes.")

    if signature == "NotSigned" and any(
            marker in path for marker in USER_WRITABLE_MARKERS):
        add("UNSIGNED_IN_USER_LOCATION", "medium",
            "Application non signee dans un dossier utilisateur.")

    return indicators


def assess(indicators):
    """Niveau de risque de repli d'apres la gravite des indicateurs."""
    severities = {i["severity"] for i in indicators}
    if "high" in severities:
        return "RISQUE_ELEVE"
    if "medium" in severities or len(indicators) >= 2:
        return "SUSPECT"
    return "A_VERIFIER" if indicators else "AUCUN_INDICATEUR_DETECTE"


def analyze_application(path, display_name=None, display_path=None):
    """Analyse statique d'un executable : empreinte, signature, en-tete PE, entropie, emplacement."""
    path = Path(path).expanduser().resolve()
    # hash, signature, regles fichier
    file_result = analyze_file(path, display_name, display_path)
    pe_info = read_pe_info(path)

    app_indicators = detect_application_risks(file_result, pe_info)
    indicators = file_result["risk_indicators"] + app_indicators

    # Les regles "fichier" utilisent A_VERIFIER ; on harmonise ici.
    level = assess(indicators)
    if any(i["severity"] == "medium" for i in file_result["risk_indicators"]):
        level = max(
            level, "SUSPECT",
            key=["AUCUN_INDICATEUR_DETECTE", "A_VERIFIER",
                 "SUSPECT", "RISQUE_ELEVE"].index)

    return {
        "application": file_result["file_name"],
        "file_path": file_result["file_path"],
        "sha256": file_result["sha256"],
        "size_bytes": file_result["size_bytes"],
        "digital_signature": file_result["digital_signature"],
        "pe_header_valid": pe_info["is_pe"],
        "entropy": pe_info["entropy"],
        "assessment": level,
        "risk_indicators_count": len(indicators),
        "risk_indicators": indicators,
        "executed": False,
        "notice": (
            "Analyse statique limitee : le comportement a l'execution "
            "n'est pas observe ici. Aucun indicateur ne signifie pas "
            "que l'application est sure."
        ),
    }


def analyze_running_applications(limit=None):
    """Analyse les executables distincts de la derniere collecte."""
    files = list(RAW_DIR.glob("processes_*.json"))
    if not files:
        raise FileNotFoundError(f"Aucune collecte dans {RAW_DIR}")
    latest = max(files, key=lambda f: f.stat().st_mtime)

    with latest.open(encoding="utf-8") as file:
        processes = json.load(file)

    paths = sorted({p["executable"] for p in processes if p.get("executable")})
    if limit:
        paths = paths[:limit]

    results, errors = [], []
    for exe in paths:
        try:
            results.append(analyze_application(Path(exe)))
        except (OSError, ValueError) as error:
            errors.append({"file_path": exe, "error": str(error)})

    return {
        "analysis_time": datetime.now().astimezone().isoformat(),
        "source_collection": latest.name,
        "applications_examined": len(results),
        "to_review": sum(r["risk_indicators_count"] > 0 for r in results),
        "errors_count": len(errors),
        "applications": results,
        "errors": errors,
        "notice": "Aucune application n'a ete executee, arretee ou modifiee.",
    }


def main():
    parser = argparse.ArgumentParser(
        description="Cubernoyau - Analyse statique d'applications")
    parser.add_argument("path", nargs="?", help="Executable a examiner")
    parser.add_argument("--running", action="store_true",
                        help="Analyser les executables de la derniere collecte")
    parser.add_argument("--limit", type=int, help="Nombre max (avec --running)")
    args = parser.parse_args()

    if args.running:
        result = analyze_running_applications(args.limit)
        report = save_report(result, "application_analysis")
        print("\n=== APPLICATIONS EN COURS : ANALYSE CUBERNOYAU ===")
        print(f"Applications analysees : {result['applications_examined']}")
        print(f"A verifier             : {result['to_review']}")
        print(f"Erreurs                : {result['errors_count']}")
    elif args.path:
        result = analyze_application(args.path)
        report = save_report(result, "application_analysis")
        print("\n=== ANALYSE D'APPLICATION CUBERNOYAU ===")
        print(f"Application : {result['application']}")
        print(f"SHA-256     : {result['sha256']}")
        print(f"Signature   : {result['digital_signature'].get('status')}")
        print(f"En-tete PE  : {'valide' if result['pe_header_valid'] else 'absent'}")
        print(f"Entropie    : {result['entropy']}")
        print(f"Evaluation  : {result['assessment']}")
        for ind in result["risk_indicators"]:
            print(f"- [{ind['severity']}] {ind['code']} : {ind['reason']}")
    else:
        parser.error("Fournir un chemin ou --running")

    print("Execution   : non")
    print(f"Rapport     : {report}")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, PermissionError, ValueError, OSError) as error:
        print(f"Erreur : {error}")
        sys.exit(1)
