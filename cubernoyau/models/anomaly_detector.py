
import json
from datetime import datetime
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler


from cubernoyau.config.settings import BASE_DIR, DATA_DIR  # noqa: E402,F401
INPUT_FILE = DATA_DIR / "runtime" / "processed" / "process_features.json"
OUTPUT_DIR = DATA_DIR / "runtime" / "processed"

FEATURE_COLUMNS = [
    "has_executable_path",
    "executable_path_length",
    "name_length",
    "process_age_log",
    "has_parent_process",
    "is_system_account",
    "cpu_log",
    "memory_log",
    "threads_log",
]


def main():
    """Ligne de commande : detecte les anomalies de la derniere collecte."""
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Fichier introuvable : {INPUT_FILE}"
        )

    with INPUT_FILE.open("r", encoding="utf-8") as file:
        processes = json.load(file)

    if len(processes) < 10:
        raise ValueError(
            "Il faut au moins 10 processus pour ce test."
        )

    # Construire la matrice des caracteristiques.
    X = np.array(
        [
            [
                float(process.get(column, 0) or 0)
                for column in FEATURE_COLUMNS
            ]
            for process in processes
        ],
        dtype=float,
    )

    # Imputation, normalisation et detection d'anomalies.
    model = make_pipeline(
        SimpleImputer(strategy="median"),
        StandardScaler(),
        IsolationForest(
            n_estimators=150,
            contamination=0.05,
            random_state=42,
        ),
    )

    model.fit(X)

    detector = model.named_steps["isolationforest"]
    transformed_X = model[:-1].transform(X)

    predictions = detector.predict(transformed_X)
    scores = detector.decision_function(transformed_X)

    results = []
    analysis_time = datetime.now().astimezone().isoformat()

    for process, prediction, score in zip(
        processes, predictions, scores
    ):
        results.append({
            "pid": process.get("pid"),
            "name": process.get("name"),
            "executable": process.get("executable"),
            "parent_name": process.get("parent_name"),
            "username": process.get("username"),
            "anomaly": bool(prediction == -1),
            "anomaly_score": round(float(score), 6),
            "analysis_time": analysis_time,
            "warning": (
                "Anomalie statistique a verifier ; "
                "ce resultat ne prouve pas un malware."
            ),
        })

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_file = OUTPUT_DIR / "anomaly_results.json"

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(
            results,
            file,
            indent=4,
            ensure_ascii=False,
        )

    anomalies = [
        item for item in results if item["anomaly"]
    ]

    print(f"Processus analyses : {len(results)}")
    print(f"Anomalies statistiques : {len(anomalies)}")
    print(f"Resultats enregistres : {output_file}")
    print("\nProcessus signales pour verification :")

    for item in sorted(
        anomalies,
        key=lambda item: item["anomaly_score"]
    )[:15]:
        print(
            f"PID={item['pid']} | "
            f"Nom={item['name']} | "
            f"Parent={item['parent_name']} | "
            f"Score={item['anomaly_score']}"
        )

    print(
        "\nImportant : les resultats sont des anomalies statistiques, "
        "pas des verdicts de malware."
    )


if __name__ == "__main__":
    main()
