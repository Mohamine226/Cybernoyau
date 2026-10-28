"""Stockage SQLite des alertes et des analyses."""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


def _now():
    """Horodatage UTC au format ISO 8601."""
    return datetime.now(timezone.utc).isoformat()


class Database:
    """Base SQLite partagee par tout le projet (alertes, analyses, listes, modeles, reglages). Un verrou rend les appels sur de multiples fils d'execution surs."""
    def __init__(self, path):
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        """Cree les tables si elles n'existent pas encore (idempotent)."""
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    title TEXT NOT NULL,
                    level TEXT NOT NULL,
                    score REAL NOT NULL,
                    details TEXT NOT NULL,
                    acknowledged INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    target TEXT NOT NULL,
                    level TEXT NOT NULL,
                    score REAL NOT NULL,
                    report TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS known_hashes (
                    sha256 TEXT PRIMARY KEY, label TEXT NOT NULL,
                    source TEXT NOT NULL, added_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS samples (
                    sha256 TEXT PRIMARY KEY, label INTEGER NOT NULL,
                    source TEXT NOT NULL, features TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS models (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL, path TEXT NOT NULL,
                    n_samples INTEGER NOT NULL, metrics TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL
                );
                """
            )

    # ---- alertes
    def add_alert(self, source, title, level, score, details):
        """Insere une nouvelle alerte et retourne son identifiant."""
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT INTO alerts (created_at, source, title, level, score,"
                " details) VALUES (?, ?, ?, ?, ?, ?)",
                (_now(), source, title, level, score,
                 json.dumps(details, ensure_ascii=False, default=str)),
            )
            return cursor.lastrowid

    @staticmethod
    def _alert_row(row):
        """Convertit une ligne SQL d'alerte en dictionnaire (JSON decode)."""
        item = dict(row)
        item["details"] = json.loads(item["details"])
        item["acknowledged"] = bool(item["acknowledged"])
        return item

    def list_alerts(self, level=None, acknowledged=None, limit=200):
        """Alertes les plus recentes, filtrables par niveau et statut."""
        query, params = "SELECT * FROM alerts WHERE 1=1", []
        if level:
            query += " AND level = ?"
            params.append(level)
        if acknowledged is not None:
            query += " AND acknowledged = ?"
            params.append(int(acknowledged))
        query += " ORDER BY id DESC LIMIT ?"
        params.append(int(limit))
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._alert_row(r) for r in rows]

    def acknowledge_alert(self, alert_id):
        """Passe une alerte au statut acquittee ; retourne False si elle n'existe pas."""
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?",
                (alert_id,))
            return cursor.rowcount > 0

    # ---- analyses
    def add_scan(self, kind, target, level, score, report):
        """Enregistre une analyse (rapport complet en JSON) et retourne son identifiant."""
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT INTO scans (created_at, kind, target, level, score,"
                " report) VALUES (?, ?, ?, ?, ?, ?)",
                (_now(), kind, target[:500], level, score,
                 json.dumps(report, ensure_ascii=False, default=str)),
            )
            return cursor.lastrowid

    def list_scans(self, limit=100, with_report=False):
        """Resume des analyses recentes."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?",
                (int(limit),)).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            if with_report:
                item["report"] = json.loads(item["report"])
            else:
                item.pop("report")
            items.append(item)
        return items

    def get_scan(self, scan_id):
        """Retourne une analyse complete par identifiant, ou None."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["report"] = json.loads(item["report"])
        return item

    def counts(self):
        """Compteurs pour le tableau de bord (alertes ouvertes, analyses...)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT"
                " SUM(acknowledged = 0) AS open_alerts,"
                " SUM(acknowledged = 0 AND level = 'RISQUE_ELEVE') AS open_high,"
                " SUM(acknowledged = 0 AND level = 'SUSPECT') AS open_suspect,"
                " COUNT(*) AS total_alerts FROM alerts").fetchone()
            scans = self._conn.execute(
                "SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
        return {
            "open_alerts": row["open_alerts"] or 0,
            "open_high": row["open_high"] or 0,
            "open_suspect": row["open_suspect"] or 0,
            "total_alerts": row["total_alerts"] or 0,
            "scans": scans,
        }

    # ---- base de hachages malveillants connus
    def add_known_hashes(self, rows):
        """rows : iterable de (sha256, label, source). Retourne le nombre ajoute."""
        now = _now()
        data = [(h.lower(), l, src, now) for h, l, src in rows]
        with self._lock, self._conn:
            before = self._conn.total_changes
            self._conn.executemany(
                "INSERT OR IGNORE INTO known_hashes VALUES (?, ?, ?, ?)", data)
            return self._conn.total_changes - before

    def lookup_hash(self, sha256):
        """Etiquette d'une empreinte malveillante connue, ou None."""
        with self._lock:
            row = self._conn.execute(
                "SELECT label FROM known_hashes WHERE sha256 = ?",
                (sha256.lower(),)).fetchone()
        return row["label"] if row else None

    def remove_known_hash(self, sha256):
        """Retire une empreinte de la liste des malwares connus (retour 'sain')."""
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM known_hashes WHERE sha256 = ?",
                               (sha256.lower(),))

    def count_known_hashes(self):
        """Nombre d'empreintes malveillantes connues."""
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) AS n FROM known_hashes").fetchone()["n"]

    # ---- echantillons d'entrainement (caracteristiques uniquement)
    def upsert_sample(self, sha256, label, source, features):
        """Ajoute ou remplace un echantillon d'entrainement (caracteristiques seulement)."""
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO samples VALUES (?, ?, ?, ?, ?)",
                (sha256.lower(), int(label), source[:80],
                 json.dumps(features), _now()))

    def has_sample(self, sha256):
        """True si l'empreinte a deja un echantillon d'entrainement."""
        with self._lock:
            return self._conn.execute(
                "SELECT 1 FROM samples WHERE sha256 = ?",
                (sha256.lower(),)).fetchone() is not None

    def sample_counts(self):
        """Nombre d'echantillons par classe et par source."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT label, source, COUNT(*) AS n FROM samples "
                "GROUP BY label, source").fetchall()
        out = {"total": 0, "malware": 0, "benign": 0, "by_source": {}}
        for r in rows:
            out["total"] += r["n"]
            out["malware" if r["label"] == 1 else "benign"] += r["n"]
            kind = r["source"].split(":")[0]
            out["by_source"][kind] = out["by_source"].get(kind, 0) + r["n"]
        return out

    def all_samples(self):
        """Tous les echantillons : (empreinte, etiquette, source, caracteristiques)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT sha256, label, source, features FROM samples").fetchall()
        return [(r["sha256"], r["label"], r["source"], json.loads(r["features"]))
                for r in rows]

    # ---- modeles
    @staticmethod
    def _model_row(row):
        """Convertit une ligne SQL de modele en dictionnaire."""
        item = dict(row)
        item["metrics"] = json.loads(item["metrics"])
        item["active"] = bool(item["active"])
        return item

    def add_model(self, path, n_samples, metrics, active):
        """Enregistre un modele entraine ; `active` le rend immediatement actif."""
        with self._lock, self._conn:
            if active:
                self._conn.execute("UPDATE models SET active = 0")
            cur = self._conn.execute(
                "INSERT INTO models (created_at, path, n_samples, metrics, active)"
                " VALUES (?, ?, ?, ?, ?)",
                (_now(), str(path), n_samples, json.dumps(metrics), int(active)))
            return cur.lastrowid

    def set_active_model(self, model_id):
        """Active un modele donne (les autres sont desactives)."""
        with self._lock, self._conn:
            if not self._conn.execute("SELECT 1 FROM models WHERE id = ?",
                                      (model_id,)).fetchone():
                return False
            self._conn.execute("UPDATE models SET active = (id = ?)", (model_id,))
            return True

    def active_model(self):
        """Modele Cubernoyau actif, ou None."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM models WHERE active = 1").fetchone()
        return self._model_row(row) if row else None

    def list_models(self):
        """Les 50 derniers modeles Cubernoyau, du plus recent au plus ancien."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM models ORDER BY id DESC LIMIT 50").fetchall()
        return [self._model_row(r) for r in rows]

    def last_model_samples(self):
        """Nombre d'echantillons du dernier entrainement (pour l'entrainement automatique)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT n_samples FROM models ORDER BY id DESC LIMIT 1").fetchone()
        return row["n_samples"] if row else 0

    # ---- reglages
    def get_setting(self, key, default=None):
        """Lit un reglage (cle/valeur) ; `default` si absent."""
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key, value):
        """Ecrit un reglage (cle/valeur)."""
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO settings VALUES (?, ?)", (key, str(value)))

    def close(self):
        """Ferme la connexion."""
        with self._lock:
            self._conn.close()
