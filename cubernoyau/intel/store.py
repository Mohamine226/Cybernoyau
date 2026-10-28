"""Stockage du renseignement (SQLite) : empreintes, liens, cache des API externes.

Ce module AJOUTE ses tables a la base existante (meme fichier que les alertes) :
 - known_hashes   (cree par storage.database) : empreintes de malwares connus ;
 - benign_hashes  : empreintes de fichiers connus comme sains (information seulement) ;
 - known_urls     : liens exacts connus (cle normalisee, voir urls.py) ;
 - known_hosts    : domaines / adresses IP connus comme dangereux ;
 - intel_files    : fichiers de listes deja importes (evite de re-importer a chaque demarrage) ;
 - online_cache   : reponses des API externes, pour ne pas re-interroger pendant N heures.
"""

import json
import time

from cubernoyau.intel.urls import normalize_url, split_host

# Taille des lots d'insertion : equilibre vitesse / memoire pour des listes de millions de lignes.
BATCH = 20000


class IntelStore:
    """Acces aux listes locales de renseignement et au cache des services en ligne."""
    def __init__(self, db):
        self.db = db
        with db._lock, db._conn:
            db._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS benign_hashes (
                    sha256 TEXT PRIMARY KEY, source TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS known_urls (
                    url_key TEXT PRIMARY KEY, url TEXT NOT NULL,
                    kind TEXT NOT NULL, source TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS known_hosts (
                    host TEXT PRIMARY KEY, kind TEXT NOT NULL, source TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS intel_files (
                    path TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
                    kind TEXT NOT NULL, rows INTEGER NOT NULL, imported_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS online_cache (
                    provider TEXT NOT NULL, key TEXT NOT NULL,
                    payload TEXT NOT NULL, fetched_at REAL NOT NULL,
                    PRIMARY KEY (provider, key)
                );
                """)

    # ------------------------------------------------------------------ empreintes
    def add_malware_hashes(self, rows):
        """rows : iterable de (sha256, etiquette, source). Retourne le nombre ajoute."""
        added, batch = 0, []
        for row in rows:
            batch.append(row)
            if len(batch) >= BATCH:
                added += self.db.add_known_hashes(batch)
                batch = []
        if batch:
            added += self.db.add_known_hashes(batch)
        return added

    def add_benign_hashes(self, rows):
        """rows : iterable de (sha256, source). Retourne le nombre ajoute."""
        added, batch = 0, []

        def flush():
            """Ecrit le lot courant dans la base."""
            nonlocal added, batch
            with self.db._lock, self.db._conn:
                before = self.db._conn.total_changes
                self.db._conn.executemany(
                    "INSERT OR IGNORE INTO benign_hashes VALUES (?, ?)", batch)
                added += self.db._conn.total_changes - before
            batch = []

        for sha, source in rows:
            batch.append((sha.lower(), source))
            if len(batch) >= BATCH:
                flush()
        if batch:
            flush()
        return added

    def lookup_malware_hash(self, sha256):
        """Etiquette de la liste de malwares connus, ou None."""
        return self.db.lookup_hash(sha256)

    def lookup_benign_hash(self, sha256):
        """Source de la liste de fichiers sains, ou None."""
        with self.db._lock:
            row = self.db._conn.execute(
                "SELECT source FROM benign_hashes WHERE sha256 = ?", (sha256.lower(),)).fetchone()
        return row["source"] if row else None

    # ------------------------------------------------------------------ liens
    def add_urls(self, rows):
        """rows : iterable de (url, kind, source). kind = malware | phishing | c2.

        Le lien exact est indexe, ainsi que son hote : un domaine entier peut etre
        signale (ex. un site piege) meme si le chemin exact n'a jamais ete vu.
        Retourne (liens ajoutes, hotes ajoutes).
        """
        added_u = added_h = 0
        for chunk in _chunks(rows, BATCH):
            urls, hosts = [], []
            for url, kind, source in chunk:
                key, host = normalize_url(url)
                if not key:
                    continue
                # Un lien reduit a un hote nu (ex. domaine ThreatFox) devient un hote signale.
                if key == host and "/" not in url.split("://", 1)[-1].rstrip("/"):
                    hosts.append((host, kind, source))
                else:
                    urls.append((key, url[:2000], kind, source))
            with self.db._lock, self.db._conn:
                before = self.db._conn.total_changes
                self.db._conn.executemany("INSERT OR IGNORE INTO known_urls VALUES (?, ?, ?, ?)", urls)
                added_u += self.db._conn.total_changes - before
                before = self.db._conn.total_changes
                self.db._conn.executemany("INSERT OR IGNORE INTO known_hosts VALUES (?, ?, ?)", hosts)
                added_h += self.db._conn.total_changes - before
        return added_u, added_h

    def add_hosts(self, rows):
        """rows : iterable de (hote, kind, source)."""
        with self.db._lock, self.db._conn:
            before = self.db._conn.total_changes
            self.db._conn.executemany(
                "INSERT OR IGNORE INTO known_hosts VALUES (?, ?, ?)",
                [(h.lower(), k, s) for h, k, s in rows])
            return self.db._conn.total_changes - before

    def lookup_url(self, raw_url):
        """Cherche un lien dans les listes locales.

        Retourne {"match": "url"|"host", "kind", "source"} ou None. Une correspondance
        exacte du lien est plus precise qu'une correspondance sur l'hote seul.
        """
        key, host = normalize_url(raw_url)
        if not key:
            return None
        with self.db._lock:
            row = self.db._conn.execute(
                "SELECT kind, source FROM known_urls WHERE url_key = ?", (key,)).fetchone()
            if row:
                return {"match": "url", "kind": row["kind"], "source": row["source"]}
            row = self.db._conn.execute(
                "SELECT kind, source FROM known_hosts WHERE host = ?", (host,)).fetchone()
        return {"match": "host", "kind": row["kind"], "source": row["source"]} if row else None

    # ------------------------------------------------------------------ suivi des fichiers de listes
    def file_is_current(self, path, fingerprint):
        """True si ce fichier de liste a deja ete importe dans son etat actuel."""
        with self.db._lock:
            row = self.db._conn.execute(
                "SELECT fingerprint FROM intel_files WHERE path = ?", (str(path),)).fetchone()
        return bool(row and row["fingerprint"] == fingerprint)

    def mark_file(self, path, fingerprint, kind, rows):
        """Memorise l'import d'un fichier de liste (empreinte, nombre de lignes)."""
        with self.db._lock, self.db._conn:
            self.db._conn.execute(
                "INSERT OR REPLACE INTO intel_files VALUES (?, ?, ?, ?, ?)",
                (str(path), fingerprint, kind, rows, time.time()))

    def files(self):
        """Fichiers de listes deja importes."""
        with self.db._lock:
            rows = self.db._conn.execute(
                "SELECT path, kind, rows, imported_at FROM intel_files ORDER BY imported_at DESC").fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ cache des API externes
    def cache_get(self, provider, key, max_age_hours):
        """Reponse en cache d'un service (None si absente ou trop ancienne)."""
        with self.db._lock:
            row = self.db._conn.execute(
                "SELECT payload, fetched_at FROM online_cache WHERE provider = ? AND key = ?",
                (provider, key)).fetchone()
        if row and time.time() - row["fetched_at"] < max_age_hours * 3600:
            return json.loads(row["payload"])
        return None

    def cache_set(self, provider, key, payload):
        """Met une reponse valide en cache."""
        with self.db._lock, self.db._conn:
            self.db._conn.execute(
                "INSERT OR REPLACE INTO online_cache VALUES (?, ?, ?, ?)",
                (provider, key, json.dumps(payload), time.time()))

    # ------------------------------------------------------------------ bilan
    def counts(self):
        """Nombre d'elements dans chaque liste."""
        def one(sql):
            """Resultat scalaire d'une requete COUNT."""
            with self.db._lock:
                return self.db._conn.execute(sql).fetchone()[0]
        return {
            "malware_hashes": self.db.count_known_hashes(),
            "benign_hashes": one("SELECT COUNT(*) FROM benign_hashes"),
            "malicious_urls": one("SELECT COUNT(*) FROM known_urls"),
            "malicious_hosts": one("SELECT COUNT(*) FROM known_hosts"),
            "cached_answers": one("SELECT COUNT(*) FROM online_cache"),
        }


def _chunks(iterable, size):
    """Decoupe un iterable en listes de `size` elements (sans tout charger en memoire)."""
    chunk = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk
