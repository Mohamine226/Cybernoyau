"""Regles sur les connexions reseau, regroupees par processus."""

from collections import defaultdict

BROWSERS = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "chrome", "firefox",
}
COMMON_PORTS = {
    20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995,
    3478, 3479, 5222, 5228, 8080, 8443,
}
TEMP_MARKERS = (
    "\\temp\\", "\\downloads\\", "\\users\\public\\", "/tmp/", "/downloads/",
)
ACTIVE_STATES = {"ESTABLISHED", "SYN_SENT", "SYN_RECV"}


def _ind(code, severity, reason):
    """Construit un indicateur {code, severity, reason}."""
    return {"code": code, "severity": severity, "reason": reason}


def analyze_connections(connections):
    """Retourne une liste de constats par processus (avec indicateurs)."""
    groups = defaultdict(list)
    for conn in connections:
        if conn.get("external") and conn.get("status") in ACTIVE_STATES:
            groups[(conn.get("pid"), conn.get("process"))].append(conn)

    findings = []
    for (pid, name), conns in groups.items():
        exe = (conns[0].get("executable") or "")
        exe_lower = exe.lower()
        destinations = {c["remote_ip"] for c in conns}
        indicators = []

        if any(marker in exe_lower for marker in TEMP_MARKERS):
            indicators.append(_ind(
                "EXTERNAL_CONNECTION_FROM_TEMP_LOCATION", "medium",
                "Programme situe dans un dossier temporaire ou de "
                "telechargement avec une connexion vers Internet."))

        uncommon = sorted({
            c["remote_port"] for c in conns
            if c["remote_port"] not in COMMON_PORTS
        })
        if uncommon:
            indicators.append(_ind(
                "UNCOMMON_REMOTE_PORT", "low",
                "Connexion vers un port peu courant : "
                + ", ".join(str(p) for p in uncommon[:5]) + "."))

        if (name or "").lower() not in BROWSERS:
            if len(destinations) >= 100:
                indicators.append(_ind(
                    "MANY_EXTERNAL_DESTINATIONS", "medium",
                    f"{len(destinations)} destinations externes distinctes "
                    "pour un seul processus."))
            elif len(destinations) >= 40:
                indicators.append(_ind(
                    "MANY_EXTERNAL_DESTINATIONS", "low",
                    f"{len(destinations)} destinations externes distinctes "
                    "pour un seul processus."))

        findings.append({
            "pid": pid,
            "process": name,
            "executable": exe or None,
            "external_connections": len(conns),
            "destinations": sorted(destinations)[:10],
            "indicators": indicators,
        })

    return findings
