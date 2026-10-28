
import json
import time
import psutil

from datetime import datetime, timezone
from pathlib import Path


from cubernoyau.config.settings import BASE_DIR, DATA_DIR  # noqa: E402,F401
OUTPUT_DIR = DATA_DIR / "runtime" / "raw"


def collect_processes(include_cmdline=False):
    """Collecte des informations detaillees sur les processus Windows."""

    processes = []
    collected_at = datetime.now(timezone.utc).isoformat()

    # Recuperer les processus actuellement accessibles.
    process_objects = list(
        psutil.process_iter(
            ["pid", "ppid", "name", "exe", "username",
             "status", "create_time"]
        )
    )

    # Premiere lecture necessaire pour mesurer le CPU.
    for process in process_objects:
        try:
            process.cpu_percent(interval=None)
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            pass

    # Laisser un court intervalle pour obtenir une mesure CPU.
    time.sleep(0.5)

    for process in process_objects:
        try:
            with process.oneshot():
                info = process.info

                try:
                    cpu_percent = process.cpu_percent(interval=None)
                except psutil.Error:
                    cpu_percent = None

                try:
                    memory = process.memory_info()
                    memory_rss_bytes = memory.rss
                except psutil.Error:
                    memory_rss_bytes = None

                try:
                    num_threads = process.num_threads()
                except psutil.Error:
                    num_threads = None

                try:
                    parent = process.parent()
                    parent_name = parent.name() if parent else None
                except psutil.Error:
                    parent_name = None

                cmdline = None
                if include_cmdline:
                    # Uniquement en memoire pour les regles de detection ;
                    # jamais enregistre (peut contenir des secrets).
                    try:
                        cmdline = " ".join(process.cmdline())[:2000]
                    except psutil.Error:
                        cmdline = None

                created_at = None
                if info.get("create_time") is not None:
                    created_at = datetime.fromtimestamp(
                        info["create_time"],
                        tz=timezone.utc
                    ).isoformat()

                processes.append({
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid"),
                    "name": info.get("name"),
                    "executable": info.get("exe"),
                    "username": info.get("username"),
                    "status": info.get("status"),
                    "created_at": created_at,
                    "collected_at": collected_at,
                    "cpu_percent": cpu_percent,
                    "memory_rss_bytes": memory_rss_bytes,
                    "num_threads": num_threads,
                    "parent_name": parent_name,
                    "cmdline": cmdline,
                })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            # Un processus peut disparaitre pendant la collecte.
            continue

    return processes


def save_processes(processes):
    """Enregistre les donnees dans un fichier JSON horodate."""

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = OUTPUT_DIR / f"processes_{timestamp}.json"

    # La ligne de commande n'est jamais ecrite sur disque.
    processes = [
        {key: value for key, value in item.items() if key != "cmdline"}
        for item in processes
    ]

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(
            processes,
            file,
            indent=4,
            ensure_ascii=False
        )

    return output_file


if __name__ == "__main__":
    results = collect_processes()
    output_file = save_processes(results)

    print(f"Nombre de processus collectes : {len(results)}")
    print(f"Fichier enregistre : {output_file}")

    print("\nExemples de mesures :")
    for process in results[:5]:
        print(
            f"PID={process['pid']} | "
            f"Nom={process['name']} | "
            f"CPU={process['cpu_percent']} % | "
            f"Memoire={process['memory_rss_bytes']} octets | "
            f"Threads={process['num_threads']} | "
            f"Parent={process['parent_name']}"
        )

    print("\nCollecte terminee.")
