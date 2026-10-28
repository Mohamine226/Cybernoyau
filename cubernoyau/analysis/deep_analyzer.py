"""Cubernoyau - Moteur d'analyse statique profonde (tout type, toute taille).

Le fichier est lu en flux (blocs de 1 Mo) : SHA-256 et entropie portent sur
le fichier ENTIER, quelle que soit sa taille ; la recherche de motifs porte
sur le debut et la fin (budget MAX_CONTENT_SCAN_MB), ou la totalite des
fichiers plus petits. Rien n'est execute.
"""

import hashlib
import ipaddress
import math
import re
import time
import zipfile
from collections import defaultdict
from pathlib import Path

import numpy as np

from cubernoyau.config import settings

from cubernoyau.analysis.rules import (CAPABILITIES, MIN_HITS, SUSPICIOUS_GROUPS,
                            RuleSet)

CHUNK = 1 << 20
EXEC_TYPES = {"pe", "elf", "macho", "script"}
SCRIPT_EXT = {".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".bat", ".cmd",
              ".hta", ".py", ".sh", ".psm1"}
OOXML_EXT = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
RISKY_IN_ARCHIVE = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1",
                    ".hta", ".lnk", ".dll", ".jar", ".msi", ".apk"}
PACKER_SECTIONS = {"upx0", "upx1", "upx2", ".aspack", ".adata", ".themida",
                   ".vmp0", ".vmp1", ".petite", ".mpress1", ".mpress2",
                   ".nsp0", ".enigma1", ".boom"}
EICAR_MARK = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"  # chaine de test standard

URL_RE = re.compile(rb"https?://[a-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,200}")
IP_RE = re.compile(rb"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

_RULES = {}


def get_rules():
    """Jeu de regles courant (integrees + data/rules/*.json), construit une fois puis reutilise."""
    key = str(settings.RULES_DIR)
    if key not in _RULES:
        _RULES[key] = RuleSet(settings.RULES_DIR)
    return _RULES[key]


def reload_rules():
    """Oublie les regles en memoire : elles seront relues au prochain appel."""
    _RULES.clear()


def entropy_from_counts(counts):
    """Entropie de Shannon a partir d'un histogramme de 256 valeurs d'octets."""
    total = counts.sum()
    if total == 0:
        return 0.0
    p = counts[counts > 0] / total
    return float(-(p * np.log2(p)).sum())


def detect_type(head, name):
    """Reconnait le type de fichier par ses premiers octets (signature), pas par son extension qui peut mentir."""
    ext = Path(name).suffix.lower()
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
        return "macho"
    if head[:4] == b"%PDF":
        return "pdf"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if head[:4] == b"PK\x03\x04":
        return "ooxml" if ext in OOXML_EXT else "zip"
    if head[:4] == b"L\x00\x00\x00":
        return "lnk"
    if ext in SCRIPT_EXT or head[:2] == b"#!":
        return "script"
    return "text" if _printable_ratio(head) > 0.9 else "binary"


def _printable_ratio(data):
    """Part des octets qui sont du texte imprimable (distingue texte et binaire)."""
    if not data:
        return 1.0
    arr = np.frombuffer(data, dtype=np.uint8)
    return float(((arr >= 32) & (arr < 127) | (arr == 9) | (arr == 10) | (arr == 13)).mean())


def _ind(code, severity, reason):
    """Construit un indicateur {code, severity, reason}."""
    return {"code": code, "severity": severity, "reason": reason}


# ------------------------------------------------------------------ flux
def _stream(path, size, rules, budget):
    """Une seule passe sur le fichier : empreintes, entropie par bloc, motifs et indices (liens, IP) sur le debut et la fin."""
    sha, md5 = hashlib.sha256(), hashlib.md5()
    counts = np.zeros(256, dtype=np.int64)
    windows, found = [], defaultdict(set)
    urls, ips = set(), set()
    head_limit = budget * 2 // 3
    tail_start = max(head_limit, size - (budget - head_limit))
    carry, offset, scanned, head = b"", 0, 0, b""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            if offset == 0:
                head = chunk[:65536]
            sha.update(chunk)
            md5.update(chunk)
            bc = np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
            counts += bc
            windows.append(entropy_from_counts(bc))
            if offset < head_limit or offset + len(chunk) > tail_start:
                data = carry + chunk
                low = data.lower()
                for pattern, tags in rules.patterns.items():
                    if pattern in low:
                        for tag in tags:
                            found[tag[0]].add(tag)
                for m in URL_RE.findall(low):
                    if len(urls) < 200:
                        urls.add(m.decode("ascii", "ignore"))
                for m in IP_RE.findall(low):
                    try:
                        ip = ipaddress.ip_address(m.decode())
                    except ValueError:
                        continue
                    if ip.is_global and len(ips) < 200:
                        ips.add(str(ip))
                if EICAR_MARK in data:
                    found["eicar"].add(1)
                scanned += len(chunk)
                carry = data[-(rules.max_len - 1):]
            else:
                carry = b""
            offset += len(chunk)
    return {"sha256": sha.hexdigest(), "md5": md5.hexdigest(), "counts": counts,
            "windows": windows, "found": found, "urls": sorted(urls),
            "ips": sorted(ips), "scanned": scanned, "head": head}


# ------------------------------------------------------------------ PE
def _parse_pe(path, size):
    """Analyse l'en-tete PE (sections, imports, .NET, signature) avec pefile ; retourne {'error': ...} si malforme."""
    try:
        import pefile
    except ImportError:
        return {"error": "bibliotheque pefile absente"}
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception as error:  # fichier tronque ou volontairement malforme
        return {"error": f"{type(error).__name__}: {error}"[:200]}
    try:
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        sections = []
        with open(path, "rb") as f:
            for s in pe.sections:
                raw, length = s.PointerToRawData, min(s.SizeOfRawData, 8 << 20)
                ent = 0.0
                if raw and length and raw < size:
                    f.seek(raw)
                    data = f.read(length)
                    if data:
                        ent = entropy_from_counts(np.bincount(
                            np.frombuffer(data, dtype=np.uint8), minlength=256))
                ch = s.Characteristics
                sections.append({
                    "name": s.Name.rstrip(b"\x00").decode("latin-1")[:12],
                    "entropy": round(ent, 2), "raw_size": s.SizeOfRawData,
                    "wx": bool(ch & 0x20000000 and ch & 0x80000000)})
        imports = sum(len(e.imports) for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
        overlay = pe.get_overlay_data_start_offset()
        stamp = pe.FILE_HEADER.TimeDateStamp
        return {
            "sections": sections, "imports": imports,
            "is_dotnet": dd[14].VirtualAddress != 0,
            "has_signature_blob": dd[4].Size > 0,
            "overlay_bytes": (size - overlay) if overlay else 0,
            "timestamp_anomaly": stamp == 0 or stamp > time.time() + 86400 or stamp < 694224000,
            "is_dll": bool(pe.is_dll()),
        }
    except Exception as error:
        return {"error": f"{type(error).__name__}: {error}"[:200]}
    finally:
        pe.close()


# ------------------------------------------------------------------ conteneurs
def _inspect_container(path, ftype, found, head):
    """Inspecte archives, documents Office et PDF : macros, executables caches, contenu actif."""
    out = []
    if ftype in ("ooxml", "zip"):
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()[:5000]
                if any(n.lower().endswith("vbaproject.bin") for n in names):
                    out.append(_ind("OFFICE_MACRO_PRESENT", "medium",
                                    "Le document contient des macros (vbaProject.bin)."))
                if ftype == "zip":
                    risky = [n for n in names if Path(n).suffix.lower() in RISKY_IN_ARCHIVE]
                    if risky:
                        out.append(_ind("ARCHIVE_CONTAINS_EXECUTABLE", "low",
                                        f"L'archive contient {len(risky)} fichier(s) executable(s)/script, ex. {risky[0]}."))
                    if any(len(Path(n).suffixes) >= 2 and Path(n).suffixes[-2].lower()
                           in {".pdf", ".doc", ".docx", ".jpg", ".png", ".txt", ".xls"}
                           and Path(n).suffix.lower() in RISKY_IN_ARCHIVE for n in names):
                        out.append(_ind("ARCHIVE_DOUBLE_EXTENSION", "medium",
                                        "Une entree de l'archive imite un document (double extension)."))
                    if any(i.flag_bits & 0x1 for i in z.infolist()):
                        out.append(_ind("ARCHIVE_ENCRYPTED", "low",
                                        "Archive chiffree : contenu non analysable."))
        except (zipfile.BadZipFile, OSError):
            out.append(_ind("ARCHIVE_UNREADABLE", "low", "Archive illisible ou corrompue."))
    if ftype == "ole" and b"VBA" in head:
        out.append(_ind("OFFICE_MACRO_PRESENT", "medium", "Document Office ancien contenant des macros."))
    if ftype == "pdf":
        try:
            blob = Path(path).read_bytes()[: 8 << 20]
        except OSError:
            blob = b""
        hits = [k for k in (b"/JavaScript", b"/JS", b"/Launch", b"/EmbeddedFile") if k in blob]
        if hits:
            out.append(_ind("PDF_ACTIVE_CONTENT", "medium",
                            "PDF avec contenu actif : " + ", ".join(h.decode() for h in hits) + "."))
    return out


# ------------------------------------------------------------------ analyse
def deep_analyze(path, hash_lookup=None, classifier=None, rules=None, scan_mb=None):
    """Analyse statique profonde d'un fichier de toute taille : indicateurs, caracteristiques d'apprentissage et predictions des modeles."""
    path = Path(path)
    size = path.stat().st_size
    rules = rules or get_rules()
    budget = (scan_mb or settings.MAX_CONTENT_SCAN_MB) << 20
    # ETAPE 1 - lecture en flux : une seule passe calcule les empreintes, l'entropie et cherche
    # les motifs (sur tout le fichier s'il est petit, sinon sur son debut et sa fin).
    s = _stream(path, size, rules, budget)
    found = s["found"]
    ftype = detect_type(s["head"], path.name)
    counts = s["counts"]
    windows = s["windows"] or [0.0]
    entropy = entropy_from_counts(counts)
    partial = size > s["scanned"] and size > 0

    # ETAPE 2 - regroupement des motifs trouves : capacites offensives (injection, keylogger...),
    # noms de familles de malwares, motifs de scripts et regles personnalisees.
    caps = {g: sorted({t[2] for t in found.get("cap", set()) if t[1] == g})
            for g in CAPABILITIES}
    fams = sorted({t[1] for t in found.get("fam", set())})
    scr = {k: sorted({t[2] for t in found.get("scr", set()) if t[1] == k})
           for k in ("obfuscation", "download_exec")}
    custom = rules.custom_matches(found.get("usr", set()), ftype)

    # Un executable Windows est decortique (sections, imports...) ; au-dela de 2 Go on s'abstient.
    pe = _parse_pe(path, size) if ftype == "pe" and size < (1 << 31) else None
    is_dotnet = bool(pe and pe.get("is_dotnet"))
    exec_like = ftype in EXEC_TYPES

    # ETAPE 3 - indicateurs : chaque constat devient {code, severity, reason}. Aucun n'est une
    # preuve : c'est leur COMBINAISON (voir detection/risk_scorer.py) qui donne le niveau final.
    ind = []
    if partial:
        ind.append(_ind("PARTIAL_CONTENT_SCAN", "info",
                        f"Fichier de {size >> 20} Mo : motifs recherches sur {s['scanned'] >> 20} Mo "
                        "(debut + fin) ; hachage et entropie sur la totalite."))
    if hash_lookup:
        label = hash_lookup(s["sha256"])
        if label:
            ind.append(_ind("KNOWN_MALWARE_HASH", "critical",
                            f"L'empreinte SHA-256 figure dans la base de malwares connus ({label})."))
    if found.get("eicar"):
        ind.append(_ind("EICAR_TEST_SIGNATURE", "high",
                        "Chaine de test antivirus standard (EICAR) : fichier de test, non dangereux."))

    # --- capacites offensives : reservees aux programmes (un texte qui CITE ces mots n'est pas un
    #     programme qui les UTILISE - sinon la documentation de securite serait "malveillante").
    if exec_like:
        if fams:
            ind.append(_ind("RULE_MALWARE_FAMILY", "high",
                            "Nom de famille de malware present dans le fichier : " + ", ".join(fams) + "."))
        present = [g for g in SUSPICIOUS_GROUPS if len(caps[g]) >= MIN_HITS.get(g, 1)]
        net = bool(caps["network"])
        meta = {
            "injection": ("CAP_PROCESS_INJECTION", "medium", "Fonctions d'injection de code dans d'autres processus"),
            "keylogging": ("CAP_KEYLOGGING", "medium", "Fonctions de capture du clavier"),
            "credential_access": ("CAP_CREDENTIAL_ACCESS", "medium", "Acces aux mots de passe / identifiants"),
            "defense_evasion": ("CAP_DEFENSE_EVASION", "medium", "Modification des protections de Windows"),
            "remote_shell": ("CAP_REMOTE_SHELL", "low", "Execution de commandes a distance"),
            "webcam_mic": ("CAP_WEBCAM_MIC", "low", "Acces webcam / microphone"),
            "screen_capture": ("CAP_SCREEN_CAPTURE", "low", "Capture d'ecran"),
            "persistence": ("CAP_PERSISTENCE", "low", "Mecanismes de demarrage automatique"),
            "anti_analysis": ("CAP_ANTI_ANALYSIS", "low", "Detection de debogueur / machine virtuelle"),
        }
        for g in present:
            code, sev, text = meta[g]
            ind.append(_ind(code, sev, f"{text} ({', '.join(caps[g][:4])})."))
        if len(caps["ransomware"]) >= 1:
            ind.append(_ind("CAP_RANSOMWARE_STRINGS", "high",
                            "Chaines typiques de rancongiciel : " + ", ".join(caps["ransomware"][:3]) + "."))
        # Profil de RAT / espion : plusieurs familles de capacites offensives, surtout si le
        # programme peut aussi communiquer sur le reseau (il faut bien envoyer ce que l'on vole).
        if len(present) >= 4 or (len(present) >= 3 and net):
            ind.append(_ind("RAT_LIKE_CAPABILITY_COMBO", "high",
                            f"Profil d'outil d'acces a distance / espion : {len(present)} familles de "
                            "capacites offensives" + (" + communication reseau." if net else ".")))
        elif len(present) >= 2 and net:
            ind.append(_ind("RAT_LIKE_CAPABILITY_COMBO", "medium",
                            "Combinaison de capacites offensives et de communication reseau."))
    if ftype == "script":
        o, d = len(scr["obfuscation"]), len(scr["download_exec"])
        if o >= 1 and d >= 1:
            ind.append(_ind("SCRIPT_DOWNLOAD_EXEC", "high",
                            "Script qui telecharge/execute du code et masque son contenu."))
        elif d >= 2:
            ind.append(_ind("SCRIPT_DOWNLOAD_EXEC", "medium", "Script de telechargement et d'execution."))
        elif o >= 2:
            ind.append(_ind("SCRIPT_OBFUSCATION", "medium", "Script obfusque."))
    for rule, hits in custom:
        ind.append(_ind(f"RULE_{rule['id']}"[:60], rule.get("severity", "medium"),
                        f"Regle personnalisee « {rule.get('name', rule['id'])} » : {', '.join(hits[:4])}."))
    ind += _inspect_container(path, ftype, found, s["head"])

    # --- structure du PE : packers, sections suspectes, imports quasi absents (programme "charge"
    #     dynamiquement), date de compilation incoherente...
    if ftype == "pe":
        if pe is None:
            pass
        elif "error" in pe:
            ind.append(_ind("PE_PARSE_ERROR", "low", "En-tete PE illisible ou volontairement malforme."))
        else:
            names = {x["name"].lower() for x in pe["sections"]}
            if names & PACKER_SECTIONS:
                ind.append(_ind("PE_PACKER_SECTION", "medium",
                                "Sections typiques d'un packer : " + ", ".join(sorted(names & PACKER_SECTIONS)) + "."))
            if any(x["wx"] for x in pe["sections"]):
                ind.append(_ind("PE_WX_SECTION", "low", "Section a la fois inscriptible et executable."))
            if any(x["entropy"] >= 7.4 and x["raw_size"] > 4096 for x in pe["sections"]):
                ind.append(_ind("PE_HIGH_ENTROPY_SECTION", "low", "Section tres aleatoire (chiffree ou compressee)."))
            if not pe["is_dotnet"] and pe["imports"] < 4 and size > 20000 and not pe["is_dll"]:
                ind.append(_ind("PE_FEW_IMPORTS", "medium",
                                "Presque aucune fonction importee : typique d'un programme compresse/charge dynamiquement."))
            if pe["overlay_bytes"] > max(1 << 20, size // 2):
                ind.append(_ind("PE_LARGE_OVERLAY", "low", "Grande quantite de donnees ajoutee apres le programme."))
            if pe["timestamp_anomaly"]:
                ind.append(_ind("PE_TIMESTAMP_ANOMALY", "low", "Date de compilation nulle ou incoherente."))

    # (Les caracteristiques ci-dessous servent a l'apprentissage du modele Cubernoyau : ce sont
    #  de simples nombres, jamais le fichier lui-meme.)
    # --- vecteur de caracteristiques pour l'apprentissage
    pe_ok = bool(pe and "error" not in pe)
    secs = pe["sections"] if pe_ok else []
    nsusp = len([g for g in SUSPICIOUS_GROUPS if len(caps[g]) >= MIN_HITS.get(g, 1)])
    feats = {
        "size_log": math.log10(size + 1), "entropy_global": entropy,
        "entropy_max_window": max(windows),
        "frac_windows_gt7": float(np.mean([w > 7.0 for w in windows])),
        "nul_ratio": float(counts[0] / max(1, counts.sum())),
        "printable_ratio": _printable_ratio(s["head"]),
        "is_pe": float(ftype == "pe"), "is_dotnet": float(is_dotnet),
        "is_elf": float(ftype == "elf"), "is_script": float(ftype == "script"),
        "is_archive": float(ftype in ("zip", "ooxml")), "is_office": float(ftype in ("ooxml", "ole")),
        "n_sections": float(len(secs)),
        "max_section_entropy": max([x["entropy"] for x in secs], default=0.0),
        "has_wx": float(any(x["wx"] for x in secs)),
        "n_imports_log": math.log10(pe["imports"] + 1) if pe_ok else 0.0,
        "few_imports": float(pe_ok and not pe["is_dotnet"] and pe["imports"] < 4),
        "overlay_ratio": (pe["overlay_bytes"] / size) if pe_ok and size else 0.0,
        "packer": float(any(x["name"].lower() in PACKER_SECTIONS for x in secs)),
        "timestamp_anomaly": float(pe_ok and pe["timestamp_anomaly"]),
        "has_sig_blob": float(pe_ok and pe["has_signature_blob"]),
        "n_urls_log": math.log10(len(s["urls"]) + 1), "n_ips_log": math.log10(len(s["ips"]) + 1),
        "n_susp_groups": float(nsusp), "family_hits": float(len(fams)),
        "script_obf": float(len(scr["obfuscation"])), "script_dl": float(len(scr["download_exec"])),
    }
    for g in CAPABILITIES:
        feats[f"cap_{g}"] = float(len(caps[g]))
    feats = {k: round(float(v), 5) for k, v in feats.items()}

    ml = {"available": False}
    if classifier is not None and classifier.available:
        p = classifier.predict(feats)
        ml = {"available": True, "probability": round(p, 4), **classifier.info()}
        sev = "high" if p >= 0.90 else "medium" if p >= 0.70 else "low" if p >= 0.50 else None
        if sev:
            ind.append(_ind("ML_MALWARE_PROBABILITY", sev,
                            f"Le modele entraine estime {p:.0%} de probabilite que le fichier soit malveillant "
                            f"(modele #{ml.get('model_id')}, {ml.get('n_samples')} echantillons)."))

    return {
        "sha256": s["sha256"], "md5": s["md5"], "size_bytes": size, "file_type": ftype,
        "entropy": round(entropy, 3), "partial_scan": partial, "scanned_bytes": s["scanned"],
        "capabilities": {g: v for g, v in caps.items() if v}, "families": fams,
        "pe": pe, "iocs": {"urls": s["urls"][:10], "url_count": len(s["urls"]),
                           "public_ips": s["ips"][:10], "ip_count": len(s["ips"])},
        "features": feats, "ml": ml, "indicators": ind,
    }


FEATURE_NAMES = [
    "size_log", "entropy_global", "entropy_max_window", "frac_windows_gt7", "nul_ratio",
    "printable_ratio", "is_pe", "is_dotnet", "is_elf", "is_script", "is_archive", "is_office",
    "n_sections", "max_section_entropy", "has_wx", "n_imports_log", "few_imports",
    "overlay_ratio", "packer", "timestamp_anomaly", "has_sig_blob", "n_urls_log", "n_ips_log",
    "n_susp_groups", "family_hits", "script_obf", "script_dl",
] + [f"cap_{g}" for g in CAPABILITIES]
