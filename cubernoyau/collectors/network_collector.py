"""Collecte des connexions reseau (lecture seule, via psutil)."""

import ipaddress

import psutil


def is_external(ip):
    """True si l'adresse est publique (ni privee, ni locale)."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        address.is_private or address.is_loopback or address.is_link_local
        or address.is_multicast or address.is_unspecified or address.is_reserved
    )


def collect_connections(processes=None):
    """Retourne {available, error, connections}. Ne modifie rien."""
    try:
        raw = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError, OSError) as error:
        return {"available": False, "error": str(error), "connections": []}

    by_pid = {p.get("pid"): p for p in (processes or [])}
    connections = []

    for conn in raw:
        if not conn.raddr:
            continue

        info = by_pid.get(conn.pid)
        if info is None and conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                info = {"name": proc.name(), "executable": proc.exe()}
            except psutil.Error:
                info = {}
        info = info or {}

        remote_ip, remote_port = conn.raddr.ip, conn.raddr.port
        connections.append({
            "pid": conn.pid,
            "process": info.get("name"),
            "executable": info.get("executable"),
            "local_port": conn.laddr.port if conn.laddr else None,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "status": conn.status,
            "external": is_external(remote_ip),
        })

    return {"available": True, "error": None, "connections": connections}
