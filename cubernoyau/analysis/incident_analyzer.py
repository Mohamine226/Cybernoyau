
import json
from datetime import datetime
from pathlib import Path

from cubernoyau.config.settings import BASE_DIR, DATA_DIR  # noqa: E402,F401
RAW_DIR = DATA_DIR / "runtime" / "raw"
PROCESSED_DIR = DATA_DIR / "runtime" / "processed"
REPORT_DIR = DATA_DIR / "reports"

SYSTEM_PROCESSES = {
    "system idle process",
    "system",
    "registry",
    "smss.exe",
    "memcompression",
}


def load_json(path):
    """Lit un fichier JSON."""
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def find_latest(pattern, directory):
    """Fichier le plus recent d'un dossier selon un motif."""
    files = list(directory.glob(pattern))
    if not files:
        raise FileNotFoundError(
            f"Aucun fichier {pattern} dans {directory}"
        )
    return max(files, key=lambda item: item.stat().st_mtime)


def assess_process(process):
    """Evalue un processus d'apres ses indicateurs."""
    name = (process.get("name") or "").lower()
    path = process.get("executable") or ""

    reasons = []
    recommendations = []

    if name in SYSTEM_PROCESSES:
        reasons.append(
            "Processus systeme connu par son nom ; identite a confirmer."
        )
        recommendations.append(
            "Verifier le chemin et l'identite avant toute conclusion."
        )

    if not path:
        reasons.append(
            "Chemin de l'executable indisponible."
        )
        recommendations.append(
            "Relancer la collecte avec les autorisations necessaires "
            "si cela est approprie."
        )

    elif path.startswith("\\\\"):
        reasons.append(
            "Executable situe sur un chemin reseau."
        )
        recommendations.append(
            "Verifier si cet emplacement reseau est attendu."
        )

    elif "\\temp\\" in path.lower() or "\\downloads\\" in path.lower():
        reasons.append(
            "Executable situe dans un dossier temporaire "
            "ou de telechargement."
        )
        recommendations.append(
            "Verifier l'origine du fichier et sa signature numerique."
        )

    if not reasons:
        reasons.append(
            "Anomalie statistique detectee par le modele."
        )
        recommendations.append(
            "Verifier le chemin, la signature numerique, "
            "le processus parent et les activites associees."
        )

    recommendations.append(
        "Ne pas supprimer ni bloquer le processus sur la seule base "
        "de ce rapport."
    )

    return {
        "pid": process.get("pid"),
        "name": process.get("name"),
        "parent_name": process.get("parent_name"),
        "username": process.get("username"),
        "executable": path or None,
        "anomaly_score": process.get("anomaly_score"),
        "observations": reasons,
        "recommendations": recommendations,
    }


def main():
    """Ligne de commande : produit un rapport d'incident."""
    results_file = PROCESSED_DIR / "anomaly_results.json"
    results = load_json(results_file)

    latest_raw = find_latest("processes_*.json", RAW_DIR)
    raw_processes = load_json(latest_raw)

    # Ajouter les chemins et informations complementaires
    # de la collecte correspondante, lorsque le PID correspond.
    raw_by_pid = {
        process.get("pid"): process
        for process in raw_processes
    }

    report = []

    for result in results:
        if not result.get("anomaly"):
            continue

        raw = raw_by_pid.get(result.get("pid"), {})
        combined = {**raw, **result}

        report.append(assess_process(combined))

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = REPORT_DIR / f"incident_report_{timestamp}.json"

    with report_file.open("w", encoding="utf-8") as file:
        json.dump(
            {
                "generated_at": datetime.now().astimezone().isoformat(),
                "source_results": results_file.name,
                "source_process_collection": latest_raw.name,
                "total_processes_examined": len(results),
                "statistical_anomalies": len(report),
                "notice": (
                    "Rapport preliminaire : une anomalie statistique "
                    "ne prouve pas une infection."
                ),
                "findings": report,
            },
            file,
            indent=4,
            ensure_ascii=False,
        )

    print(f"Processus examines : {len(results)}")
    print(f"Observations a verifier : {len(report)}")
    print(f"Rapport cree : {report_file}")
    print(
        "\nRapport preliminaire genere. "
        "Aucune action n'a ete effectuee sur les processus."
    )


if __name__ == "__main__":
    main()
