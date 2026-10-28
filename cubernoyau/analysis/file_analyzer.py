
import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from cubernoyau.analysis.file_risk_detector import detect_file_risks


from cubernoyau.config.settings import BASE_DIR, DATA_DIR  # noqa: E402,F401
REPORT_DIR = DATA_DIR / "reports"

SIGNATURE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".msi", ".ps1", ".ocx", ".cab"
}


def calculate_sha256(file_path):
    """Calcule l'empreinte SHA-256 du fichier."""
    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def get_digital_signature(file_path):
    """Verifie la signature Authenticode avec PowerShell."""

    if file_path.suffix.lower() not in SIGNATURE_EXTENSIONS:
        return {
            "status": "not_checked",
            "message": "Extension non prise en charge par ce controle."
        }

    if sys.platform != "win32":
        return {
            "status": "unavailable",
            "message": "Verification Authenticode disponible sous Windows uniquement."
        }

    env = os.environ.copy()
    env["CUBERNOYAU_TARGET_FILE"] = str(file_path)

    script = r"""
$ErrorActionPreference = 'Stop'
$sig = Get-AuthenticodeSignature -LiteralPath $env:CUBERNOYAU_TARGET_FILE
$result = @{
    Status = [string]$sig.Status
    StatusMessage = [string]$sig.StatusMessage
    Signer = $null
    Issuer = $null
}
if ($null -ne $sig.SignerCertificate) {
    $result.Signer = $sig.SignerCertificate.Subject
    $result.Issuer = $sig.SignerCertificate.Issuer
}
$result | ConvertTo-Json -Compress
"""

    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            env=env,
        )

        if completed.returncode != 0:
            return {
                "status": "error",
                "message": completed.stderr.strip()
                or "Echec de la verification PowerShell."
            }

        data = json.loads(completed.stdout)

        return {
            "status": data.get("Status", "Unknown"),
            "message": data.get("StatusMessage", ""),
            "signer": data.get("Signer"),
            "issuer": data.get("Issuer"),
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "message": "Delai depasse pendant la verification."
        }
    except (OSError, json.JSONDecodeError) as error:
        return {
            "status": "error",
            "message": str(error)
        }


def analyze_file(file_path, display_name=None, display_path=None):
    """Analyse un fichier et recherche des indicateurs de risque."""

    file_path = file_path.expanduser().resolve()

    if not file_path.exists():
        raise FileNotFoundError(f"Fichier introuvable : {file_path}")

    if not file_path.is_file():
        raise ValueError(f"Ce chemin n'est pas un fichier : {file_path}")

    stat = file_path.stat()
    shown_name = display_name or file_path.name
    shown_path = display_path or str(file_path)

    result = {
        "analysis_time": datetime.now().astimezone().isoformat(),
        "file_name": shown_name,
        "file_path": shown_path,
        "extension": Path(shown_name).suffix.lower(),
        "size_bytes": stat.st_size,
        "modified_time": datetime.fromtimestamp(
            stat.st_mtime
        ).astimezone().isoformat(),
        "sha256": calculate_sha256(file_path),
        "digital_signature": get_digital_signature(file_path),
        "executed": False,
        "notice": (
            "Une signature valide ne garantit pas qu'un fichier est sain. "
            "Une absence de signature ne prouve pas qu'il est malveillant."
        ),
    }

    # Detection explicable a partir des metadonnees.
    risk_result = detect_file_risks(result)

    result["risk_assessment"] = risk_result["assessment"]
    result["risk_indicators_count"] = risk_result["risk_indicators_count"]
    result["risk_indicators"] = risk_result["indicators"]

    return result


def save_report(data, prefix):
    """Enregistre un rapport JSON horodate."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    report_file = REPORT_DIR / f"{prefix}_{timestamp}.json"

    with report_file.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)

    return report_file


def analyze_directory(directory, recursive=False):
    """Analyse les fichiers d'un dossier sans les executer."""

    directory = directory.expanduser().resolve()

    if not directory.exists():
        raise FileNotFoundError(f"Dossier introuvable : {directory}")

    if not directory.is_dir():
        raise ValueError(f"Ce chemin n'est pas un dossier : {directory}")

    iterator = directory.rglob("*") if recursive else directory.iterdir()

    results = []
    errors = []

    for path in iterator:
        if not path.is_file():
            continue

        try:
            results.append(analyze_file(path))
        except (OSError, ValueError) as error:
            errors.append({
                "file_path": str(path),
                "error": str(error)
            })

    files_to_review = sum(
        item.get("risk_indicators_count", 0) > 0
        for item in results
    )

    indicators_total = sum(
        item.get("risk_indicators_count", 0)
        for item in results
    )

    summary = {
        "analysis_time": datetime.now().astimezone().isoformat(),
        "directory": str(directory),
        "recursive": recursive,
        "files_examined": len(results),
        "files_to_review": files_to_review,
        "risk_indicators_total": indicators_total,
        "errors_count": len(errors),
        "signature_valid": sum(
            item["digital_signature"].get("status") == "Valid"
            for item in results
        ),
        "signature_not_checked": sum(
            item["digital_signature"].get("status") == "not_checked"
            for item in results
        ),
        "files": results,
        "errors": errors,
        "notice": (
            "Les indicateurs signalent des observations a verifier, "
            "pas une preuve de logiciel malveillant. "
            "Aucun fichier n'a ete execute, supprime ou modifie."
        ),
    }

    return summary


def main():
    """Ligne de commande : analyse un fichier ou dossier et ecrit un rapport."""
    parser = argparse.ArgumentParser(
        description="Cubernoyau - Analyse statique de fichiers et dossiers"
    )

    parser.add_argument(
        "path",
        help="Chemin du fichier ou du dossier a examiner"
    )

    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Analyser aussi les sous-dossiers"
    )

    args = parser.parse_args()
    target = Path(args.path).expanduser()

    if not target.exists():
        raise FileNotFoundError(f"Chemin introuvable : {target}")

    if target.is_file():
        result = analyze_file(target)
        report_file = save_report(result, "file_analysis")

        signature = result["digital_signature"]

        print("\n=== RAPPORT D'ANALYSE CUBERNOYAU ===")
        print(f"Nom                 : {result['file_name']}")
        print(f"Taille              : {result['size_bytes']} octets")
        print(f"SHA-256             : {result['sha256']}")
        print(f"Signature           : {signature.get('status')}")
        print(f"Editeur             : {signature.get('signer') or 'Non disponible'}")
        print(f"Details signature   : {signature.get('message', '')}")
        print(f"Evaluation          : {result['risk_assessment']}")
        print(f"Indicateurs detectes : {result['risk_indicators_count']}")

        for indicator in result["risk_indicators"]:
            print(
                f"- [{indicator['severity']}] "
                f"{indicator['code']} : {indicator['reason']}"
            )

        print("Execution            : non")
        print(f"Rapport              : {report_file}")

    elif target.is_dir():
        result = analyze_directory(target, args.recursive)
        report_file = save_report(result, "directory_analysis")

        print("\n=== ANALYSE DE DOSSIER CUBERNOYAU ===")
        print(f"Dossier               : {result['directory']}")
        print(f"Fichiers analyses     : {result['files_examined']}")
        print(f"Fichiers a verifier   : {result['files_to_review']}")
        print(f"Indicateurs detectes  : {result['risk_indicators_total']}")
        print(f"Signatures valides    : {result['signature_valid']}")
        print(f"Signatures ignorees   : {result['signature_not_checked']}")
        print(f"Erreurs               : {result['errors_count']}")
        print("Execution de fichiers : non")
        print(f"Rapport               : {report_file}")

    else:
        raise ValueError(
            "Le chemin n'est ni un fichier regulier ni un dossier."
        )


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, PermissionError, ValueError, OSError) as error:
        print(f"Erreur : {error}")
