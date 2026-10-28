
import json
import math
from datetime import datetime, timezone
from pathlib import Path

from cubernoyau.config.settings import BASE_DIR, DATA_DIR  # noqa: E402,F401
RAW_DIR = DATA_DIR / "runtime" / "raw"
PROCESSED_DIR = DATA_DIR / "runtime" / "processed"


def get_latest_json():
    """Trouve la collecte de processus la plus recente."""

    files = list(RAW_DIR.glob("processes_*.json"))

    if not files:
        raise FileNotFoundError(
            f"Aucun fichier de collecte trouve dans {RAW_DIR}"
        )

    return max(files, key=lambda file: file.stat().st_mtime)


def safe_number(value, default=0.0):
    """Convertit une valeur en nombre exploitable."""

    try:
        number = float(value)
        if math.isfinite(number):
            return number
    except (TypeError, ValueError):
        pass

    return default


def extract_features(process):
    """Transforme les observations en caracteristiques numeriques."""

    name = (process.get("name") or "").lower()
    executable = process.get("executable") or ""
    username = process.get("username") or ""
    status = (process.get("status") or "").lower()
    parent_name = (process.get("parent_name") or "").lower()

    age_seconds = 0.0
    created_at = process.get("created_at")

    if created_at:
        try:
            created = datetime.fromisoformat(
                created_at.replace("Z", "+00:00")
            )
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)

            age_seconds = max(
                0.0,
                (datetime.now(timezone.utc) - created).total_seconds()
            )
        except (ValueError, TypeError):
            pass

    cpu_percent = max(
        0.0, safe_number(process.get("cpu_percent"))
    )
    memory_bytes = max(
        0.0, safe_number(process.get("memory_rss_bytes"))
    )
    thread_count = max(
        0.0, safe_number(process.get("num_threads"))
    )

    return {
        "pid": process.get("pid"),
        "name": name,
        "username": username,
        "status": status,
        "parent_name": parent_name,

        "has_executable_path": int(bool(executable)),
        "executable_path_length": len(executable),
        "name_length": len(name),
        "process_age_seconds": round(age_seconds, 2),
        "has_parent_process": int(
            process.get("ppid") not in (None, 0)
        ),
        "is_system_account": int(
            "system" in username.lower()
        ),

        "cpu_percent": round(cpu_percent, 2),
        "memory_rss_bytes": int(memory_bytes),
        "num_threads": int(thread_count),

        # Transformations pour limiter l'effet des valeurs tres grandes.
        "cpu_log": round(math.log1p(cpu_percent), 6),
        "memory_log": round(math.log1p(memory_bytes), 6),
        "threads_log": round(math.log1p(thread_count), 6),
        "process_age_log": round(math.log1p(age_seconds), 6),
    }


def main():
    """Ligne de commande : extrait les caracteristiques de la derniere collecte."""
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    input_file = get_latest_json()

    with input_file.open("r", encoding="utf-8") as file:
        processes = json.load(file)

    features = [
        extract_features(process)
        for process in processes
    ]

    output_file = PROCESSED_DIR / "process_features.json"

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(
            features,
            file,
            indent=4,
            ensure_ascii=False
        )

    print(f"Fichier source : {input_file.name}")
    print(f"Processus traites : {len(features)}")
    print(f"Caracteristiques enregistrees : {output_file}")
    print("Extraction terminee.")


if __name__ == "__main__":
    main()
