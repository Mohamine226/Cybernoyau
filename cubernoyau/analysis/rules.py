"""Regles de detection par motifs : capacites, familles de malwares, scripts.

Les motifs sont cherches (sans tenir compte de la casse) en ASCII et en
UTF-16, car les chaines des programmes .NET/Windows sont souvent en UTF-16.
Regles personnalisees : data/rules/*.json, par exemple
  [{"id": "ma-regle", "name": "Mon malware", "severity": "high",
    "strings": ["chaine1", "chaine2"], "min_matches": 2,
    "types": ["pe", "script"], "description": "..."}]
"""

import json
from pathlib import Path

CAPABILITIES = {
    "injection": ["virtualallocex", "writeprocessmemory", "createremotethread",
                  "ntunmapviewofsection", "zwunmapviewofsection", "queueuserapc",
                  "setthreadcontext", "ntwritevirtualmemory", "rtlcreateuserthread"],
    "keylogging": ["getasynckeystate", "setwindowshookex", "getkeyboardstate",
                   "keylog", "getrawinputdata"],
    "screen_capture": ["copyfromscreen", "bitblt", "printwindow", "capturescreen",
                       "screenshot"],
    "webcam_mic": ["capcreatecapturewindow", "capgetdriverdescription",
                   "waveinopen", "mcisendstring"],
    "network": ["wsastartup", "internetopenurl", "urldownloadtofile",
                "httpsendrequest", "tcpclient", "webclient", "downloadfile",
                "downloadstring", "winhttpopen", "system.net.sockets",
                "httpwebrequest"],
    "persistence": ["currentversion\\run", "createservicea", "createservicew",
                    "schtasks /create", "\\startup\\", "winlogon\\shell",
                    "currentversion\\runonce"],
    "anti_analysis": ["isdebuggerpresent", "checkremotedebuggerpresent",
                      "ntqueryinformationprocess", "sbiedll.dll", "vboxservice",
                      "vmtoolsd", "vboxguest"],
    "credential_access": ["cryptunprotectdata", "login data", "logins.json",
                          "lsaenumeratelogonsessions", "sekurlsa", "wallet.dat",
                          "key4.db"],
    "remote_shell": ["redirectstandardoutput", "cmd.exe /c", "powershell.exe -",
                     "createpipe", "/bin/sh -i"],
    "defense_evasion": ["adjusttokenprivileges", "sedebugprivilege",
                        "add-mppreference", "set-mppreference",
                        "disablerealtimemonitoring", "netsh advfirewall"],
    "ransomware": ["vssadmin delete shadows", "wbadmin delete catalog",
                   "recoveryenabled no", "your files have been encrypted",
                   "decrypt your files"],
}

# Nombre minimal de motifs distincts pour qu'un groupe compte (evite les
# faux positifs sur des API courantes prises isolement).
MIN_HITS = {"injection": 2, "screen_capture": 2, "anti_analysis": 2}

# Groupes "offensifs" combines pour reconnaitre un profil de RAT/espion.
SUSPICIOUS_GROUPS = [
    "injection", "keylogging", "screen_capture", "webcam_mic", "persistence",
    "anti_analysis", "credential_access", "remote_shell", "defense_evasion",
]

FAMILIES = {
    "AsyncRAT": ["asyncrat"], "njRAT": ["njrat", "bladabindi"],
    "Quasar": ["quasar.client", "quasarrat"], "XWorm": ["xworm"],
    "Remcos": ["remcos"], "NanoCore": ["nanocore"], "DarkComet": ["darkcomet"],
    "DcRat": ["dcrat"], "WarzoneRAT": ["warzone rat", "ave_maria"],
    "NetWire": ["netwire"], "Orcus": ["orcus"], "LimeRAT": ["limerat"],
    "Revenge-RAT": ["revenge-rat"], "Blackshades": ["blackshades"],
    "PoisonIvy": ["poisonivy"], "Gh0st": ["gh0st"],
    "Meterpreter": ["metsrv", "meterpreter"],
    "Mimikatz": ["gentilkiwi", "sekurlsa::logonpasswords"],
}

SCRIPT_OBFUSCATION = ["frombase64string", "-encodedcommand", "string.fromcharcode",
                      "unescape(", "eval(", "[char]"]
SCRIPT_DOWNLOAD_EXEC = ["downloadstring", "downloadfile", "invoke-webrequest",
                        "certutil -urlcache", "bitsadmin /transfer", "mshta http",
                        "start-bitstransfer", "invoke-expression", "iex(",
                        "iex (", "wscript.shell", "adodb.stream"]


class RuleSet:
    """Index motif -> etiquettes, pret pour la recherche en flux."""

    def __init__(self, custom_dir=None):
        self.patterns = {}          # bytes -> set(tags)
        self.custom = []            # regles personnalisees valides
        for group, names in CAPABILITIES.items():
            for n in names:
                self._add(n, ("cap", group))
        for family, names in FAMILIES.items():
            for n in names:
                self._add(n, ("fam", family))
        for n in SCRIPT_OBFUSCATION:
            self._add(n, ("scr", "obfuscation"))
        for n in SCRIPT_DOWNLOAD_EXEC:
            self._add(n, ("scr", "download_exec"))
        self._load_custom(custom_dir)
        self.max_len = max(len(p) for p in self.patterns)

    def _add(self, text, tag):
        text = text.lower()
        for raw in (text.encode("utf-8"), text.encode("utf-16le")):
            self.patterns.setdefault(raw, set()).add(tag + (text,))

    def _load_custom(self, directory):
        if not directory or not Path(directory).is_dir():
            return
        for file in sorted(Path(directory).glob("*.json")):
            try:
                rules = json.loads(file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for rule in rules if isinstance(rules, list) else []:
                if not isinstance(rule, dict) or not rule.get("id") \
                        or not isinstance(rule.get("strings"), list) \
                        or not rule["strings"]:
                    continue
                self.custom.append(rule)
                for text in rule["strings"]:
                    if isinstance(text, str) and text:
                        self._add(text, ("usr", str(rule["id"])))

    def custom_matches(self, found, file_type):
        """Regles personnalisees satisfaites par les motifs trouves."""
        out = []
        for rule in self.custom:
            types = rule.get("types")
            if types and file_type not in types:
                continue
            hits = {t[2] for t in found if t[0] == "usr" and t[1] == str(rule["id"])}
            if len(hits) >= int(rule.get("min_matches", 1)):
                out.append((rule, sorted(hits)))
        return out
