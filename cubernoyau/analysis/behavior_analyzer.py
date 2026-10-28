"""Regles comportementales sur les processus (explicables, sans execution)."""

import re

from cubernoyau.analysis.file_risk_detector import detect_file_risks

OFFICE_APPS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe",
}
SCRIPT_HOSTS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "msbuild.exe",
}
POWERSHELL = {"powershell.exe", "pwsh.exe"}

IGNORED_NAMES = {"system idle process", "system"}

USER_WRITABLE_MARKERS = (
    "\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\downloads\\",
    "\\users\\public\\", "\\windows\\temp\\", "\\programdata\\",
    "/tmp/", "/downloads/",
)

ENCODED_COMMAND = re.compile(r"\s-(?:enc|ec|encodedcommand)\s", re.I)
HIDDEN_WINDOW = re.compile(r"-(?:w|windowstyle)\s+hidden", re.I)
DOWNLOAD_CRADLE = re.compile(
    r"downloadstring|downloadfile|frombase64string|invoke-expression|\biex\b",
    re.I)
CERTUTIL_DOWNLOAD = re.compile(r"certutil.*-urlcache|bitsadmin.*/transfer", re.I)

HIGH_CPU_PERCENT = 90.0
HIGH_CPU_CYCLES = 3


def _ind(code, severity, reason):
    """Construit un indicateur {code, severity, reason}."""
    return {"code": code, "severity": severity, "reason": reason}


class ProcessBehaviorAnalyzer:
    """Analyse un instantane de processus ; garde un peu d'etat (CPU)."""

    def __init__(self):
        self._cpu_streak = {}

    def reset(self):
        self._cpu_streak.clear()

    def analyze(self, processes):
        """Retourne {pid: [indicateurs]}."""
        results = {}
        alive = set()

        for proc in processes:
            pid = proc.get("pid")
            name = (proc.get("name") or "").lower()
            if name in IGNORED_NAMES:
                continue

            parent = (proc.get("parent_name") or "").lower()
            exe = proc.get("executable") or ""
            exe_lower = exe.lower()
            cmd = proc.get("cmdline") or ""
            indicators = []

            if parent in OFFICE_APPS and name in SCRIPT_HOSTS:
                indicators.append(_ind(
                    "OFFICE_SPAWNS_SCRIPT_HOST", "high",
                    f"{parent} a lance {name} : schema typique de macros "
                    "ou de documents piegés (parfois legitime)."))

            if name in POWERSHELL and cmd:
                if ENCODED_COMMAND.search(" " + cmd + " "):
                    indicators.append(_ind(
                        "POWERSHELL_ENCODED_COMMAND", "medium",
                        "PowerShell lance avec une commande encodee."))
                if HIDDEN_WINDOW.search(cmd):
                    indicators.append(_ind(
                        "POWERSHELL_HIDDEN_WINDOW", "medium",
                        "PowerShell lance avec une fenetre masquee."))

            if cmd and DOWNLOAD_CRADLE.search(cmd):
                indicators.append(_ind(
                    "DOWNLOAD_AND_EXECUTE_PATTERN", "medium",
                    "La ligne de commande contient un motif de "
                    "telechargement/execution en memoire."))
            if cmd and CERTUTIL_DOWNLOAD.search(cmd):
                indicators.append(_ind(
                    "LOLBIN_DOWNLOAD", "medium",
                    "Utilitaire Windows utilise pour telecharger un fichier."))

            if exe:
                file_view = detect_file_risks({
                    "file_name": exe.replace("\\", "/").split("/")[-1],
                    "extension": "." + name.rsplit(".", 1)[-1] if "." in name else "",
                    "file_path": exe,
                    "digital_signature": {},
                })
                for item in file_view["indicators"]:
                    if item["code"] in {
                        "MISLEADING_DOUBLE_EXTENSION",
                        "WINDOWS_LIKE_NAME_UNUSUAL_LOCATION",
                    }:
                        indicators.append(item)

                if any(m in exe_lower for m in USER_WRITABLE_MARKERS):
                    indicators.append(_ind(
                        "RUNS_FROM_USER_WRITABLE_PATH", "low",
                        "Processus lance depuis un dossier modifiable par "
                        "l'utilisateur (temporaire, telechargements, AppData)."))

            key = (pid, proc.get("created_at"))
            alive.add(key)
            cpu = proc.get("cpu_percent") or 0.0
            if cpu >= HIGH_CPU_PERCENT:
                self._cpu_streak[key] = self._cpu_streak.get(key, 0) + 1
            else:
                self._cpu_streak.pop(key, None)
            if self._cpu_streak.get(key, 0) >= HIGH_CPU_CYCLES:
                indicators.append(_ind(
                    "SUSTAINED_HIGH_CPU", "low",
                    f"CPU >= {int(HIGH_CPU_PERCENT)} % pendant "
                    f"{HIGH_CPU_CYCLES} mesures consecutives."))

            results[pid] = indicators

        for key in list(self._cpu_streak):
            if key not in alive:
                del self._cpu_streak[key]

        return results
