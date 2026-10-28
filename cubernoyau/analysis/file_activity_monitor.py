"""Detection de modifications massives de fichiers (comportement de type
rancongiciel) par comparaison d'instantanes. Lecture seule."""

import math
import os
from collections import Counter

COMPRESSED_EXT = {
    ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".jpg", ".jpeg", ".png",
    ".gif", ".webp", ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".flac",
    ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".apk", ".iso",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", "appdata", ".cache"}
ENTROPY_THRESHOLD = 7.5


def shannon_entropy(data):
    """Entropie de Shannon (0 a 8 bits/octet) : proche de 8 = contenu chiffre ou compresse."""
    if not data:
        return 0.0
    total = len(data)
    return -sum((c / total) * math.log2(c / total)
                for c in Counter(data).values())


def _ind(code, severity, reason):
    """Construit un indicateur {code, severity, reason}."""
    return {"code": code, "severity": severity, "reason": reason}


class FileActivityMonitor:
    """Detecte les modifications massives de fichiers (profil de rancongiciel) en comparant deux instantanes successifs des dossiers surveilles."""
    def __init__(self, directories, max_files=5000, max_depth=2,
                 burst_threshold=20, ext_threshold=10, entropy_sample=40):
        self.directories = [str(d) for d in directories]
        self.max_files = max_files
        self.max_depth = max_depth
        self.burst_threshold = burst_threshold
        self.ext_threshold = ext_threshold
        self.entropy_sample = entropy_sample
        self._previous = None

    def _snapshot(self):
        """Releve (date, taille) de chaque fichier des dossiers surveilles, avec limites de profondeur et de nombre."""
        files = {}

        def walk(directory, depth):
            """Parcours recursif borne d'un dossier."""
            if len(files) >= self.max_files:
                return
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if len(files) >= self.max_files:
                            return
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_file():
                                st = entry.stat()
                                files[entry.path] = (st.st_mtime_ns, st.st_size)
                            elif (entry.is_dir() and depth < self.max_depth
                                  and entry.name.lower() not in SKIP_DIRS):
                                walk(entry.path, depth + 1)
                        except OSError:
                            continue
            except OSError:
                return

        for directory in self.directories:
            walk(directory, 0)
        return files

    @staticmethod
    def _ext(path):
        """Extension en minuscules d'un chemin."""
        return os.path.splitext(path)[1].lower()

    def _high_entropy_fraction(self, paths):
        """Part des fichiers modifies dont le contenu semble chiffre (entropie elevee)."""
        sampled = high = 0
        for path in paths:
            if sampled >= self.entropy_sample:
                break
            if self._ext(path) in COMPRESSED_EXT:
                continue
            try:
                if os.path.getsize(path) < 1024:
                    continue
                with open(path, "rb") as file:
                    data = file.read(64 * 1024)
            except OSError:
                continue
            sampled += 1
            if shannon_entropy(data) >= ENTROPY_THRESHOLD:
                high += 1
        return sampled, (high / sampled if sampled else 0.0)

    def scan(self):
        """Compare a l'instantane precedent et retourne indicateurs et statistiques ; le premier appel ne fait que memoriser l'etat initial."""
        current = self._snapshot()
        previous = self._previous
        self._previous = current

        empty = {"baseline": previous is None, "created": 0, "modified": 0,
                 "deleted": 0, "entropy_sampled": 0,
                 "high_entropy_fraction": 0.0, "indicators": [],
                 "sample_paths": [], "files_watched": len(current)}
        if previous is None:
            return empty

        created = [p for p in current if p not in previous]
        deleted = [p for p in previous if p not in current]
        modified = [p for p in current
                    if p in previous and current[p] != previous[p]]
        changed = created + modified

        sampled, fraction = self._high_entropy_fraction(changed)
        indicators = []

        if len(changed) >= self.burst_threshold:
            if sampled >= 5 and fraction >= 0.6:
                indicators.append(_ind(
                    "MASS_HIGH_ENTROPY_WRITES", "high",
                    f"{len(changed)} fichiers modifies/crees en un cycle, "
                    f"dont {int(fraction * 100)} % au contenu tres aleatoire "
                    "(chiffrement possible)."))
            else:
                indicators.append(_ind(
                    "MASS_FILE_MODIFICATION", "medium",
                    f"{len(changed)} fichiers modifies ou crees en un cycle."))

        if len(deleted) >= self.burst_threshold:
            indicators.append(_ind(
                "MASS_FILE_DELETION", "medium",
                f"{len(deleted)} fichiers supprimes ou renommes en un cycle."))

        known_ext = {self._ext(p) for p in previous}
        new_ext = Counter(self._ext(p) for p in created)
        for ext, count in new_ext.items():
            if ext and ext not in known_ext and count >= self.ext_threshold:
                if len(deleted) >= self.ext_threshold:
                    indicators.append(_ind(
                        "MASS_RENAME_NEW_EXTENSION", "high",
                        f"{count} fichiers avec la nouvelle extension '{ext}' "
                        f"et {len(deleted)} fichiers disparus : renommage de "
                        "masse possible."))
                else:
                    indicators.append(_ind(
                        "MASS_NEW_EXTENSION", "medium",
                        f"{count} nouveaux fichiers avec l'extension '{ext}' "
                        "jamais vue dans les dossiers surveilles."))
                break

        return {
            "baseline": False, "created": len(created),
            "modified": len(modified), "deleted": len(deleted),
            "entropy_sampled": sampled,
            "high_entropy_fraction": round(fraction, 2),
            "indicators": indicators,
            "sample_paths": (changed + deleted)[:10],
            "files_watched": len(current),
        }
