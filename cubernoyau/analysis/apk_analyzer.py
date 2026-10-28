"""Cubernoyau - Analyse statique d'applications Android (.apk).

L'APK n'est jamais installe ni execute : on lit l'archive ZIP et on releve
les noms de permissions presents dans AndroidManifest.xml. Une permission
sensible n'est pas une preuve : beaucoup d'applications legitimes les demandent.
"""

import re
import zipfile
from pathlib import Path

PERMISSION_RE = re.compile(rb"android\.permission\.[A-Z_]{3,60}")
PERMISSION_RE_U16 = re.compile(
    "a\0n\0d\0r\0o\0i\0d\0.\0p\0e\0r\0m\0i\0s\0s\0i\0o\0n\0.\0(?:[A-Z_]\0){3,60}".encode("latin-1"))

SMS = {"READ_SMS", "RECEIVE_SMS", "SEND_SMS", "RECEIVE_MMS", "WRITE_SMS"}
DANGEROUS = SMS | {
    "READ_CONTACTS", "READ_CALL_LOG", "RECORD_AUDIO", "CAMERA",
    "ACCESS_FINE_LOCATION", "READ_PHONE_STATE", "CALL_PHONE",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "GET_ACCOUNTS",
}


def is_apk(path):
    """True si l'archive contient un AndroidManifest.xml."""
    path = Path(path)
    if not zipfile.is_zipfile(path):
        return False
    try:
        with zipfile.ZipFile(path) as z:
            return "AndroidManifest.xml" in z.namelist()
    except (zipfile.BadZipFile, OSError):
        return False


def extract_permissions(manifest_bytes):
    """Noms de permissions Android trouves dans le manifeste binaire (ASCII ou UTF-16)."""
    found = {m.decode("ascii") for m in PERMISSION_RE.findall(manifest_bytes)}
    found |= {m.decode("utf-16le") for m in PERMISSION_RE_U16.findall(manifest_bytes)}
    return sorted(p.split(".")[-1] for p in found)


def _ind(code, severity, reason):
    """Construit un indicateur {code, severity, reason}."""
    return {"code": code, "severity": severity, "reason": reason}


def analyze_apk(path):
    """Retourne la liste d'indicateurs ([] si ce n'est pas un APK)."""
    path = Path(path)
    if path.suffix.lower() != ".apk" and not is_apk(path):
        return []
    if not zipfile.is_zipfile(path):
        return [_ind("APK_INVALID_ARCHIVE", "medium",
                     "Le fichier .apk n'est pas une archive valide.")]
    out = []
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if "AndroidManifest.xml" not in names:
            return [_ind("APK_NO_MANIFEST", "medium",
                         "Archive sans AndroidManifest.xml : ce n'est pas une application Android normale.")]
        perms = set(extract_permissions(z.read("AndroidManifest.xml")))
        if any(i.flag_bits & 0x1 for i in z.infolist()):
            out.append(_ind("APK_ENCRYPTED_ENTRIES", "medium",
                            "Entrees chiffrees dans l'archive : contenu non analysable."))
    out.append(_ind("APK_PACKAGE", "info",
                    f"Application Android ; {len(perms)} permission(s) declaree(s)."))
    if "BIND_ACCESSIBILITY_SERVICE" in perms:
        out.append(_ind("APK_ACCESSIBILITY_SERVICE", "medium",
                        "Demande le service d'accessibilite : peut lire l'ecran et agir a la place de "
                        "l'utilisateur (utilise aussi par des chevaux de Troie bancaires)."))
    if "BIND_DEVICE_ADMIN" in perms:
        out.append(_ind("APK_DEVICE_ADMIN", "medium",
                        "Demande les droits d'administrateur de l'appareil (rend la desinstallation difficile)."))
    if "SYSTEM_ALERT_WINDOW" in perms:
        out.append(_ind("APK_OVERLAY", "low",
                        "Peut s'afficher par-dessus d'autres applications (technique de faux ecrans)."))
    if "REQUEST_INSTALL_PACKAGES" in perms:
        out.append(_ind("APK_INSTALLS_PACKAGES", "low",
                        "Peut demander l'installation d'autres applications."))
    sms = perms & SMS
    if len(sms) >= 2:
        out.append(_ind("APK_SMS_ACCESS", "medium",
                        "Lecture/envoi de SMS : " + ", ".join(sorted(sms)) + "."))
    dangerous = perms & DANGEROUS
    if len(dangerous) >= 6:
        out.append(_ind("APK_MANY_DANGEROUS_PERMISSIONS", "low",
                        f"{len(dangerous)} permissions sensibles demandees."))
    return out
