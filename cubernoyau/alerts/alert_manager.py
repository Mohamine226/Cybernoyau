"""Creation d'alertes avec limitation des doublons (cooldown)."""

import threading
import time

from cubernoyau.config import settings
from cubernoyau.detection.risk_scorer import LEVEL_NONE


class AlertManager:
    """Transforme un resultat d'analyse en alerte et evite de re-signaler le meme element pendant un delai (cooldown)."""
    def __init__(self, database, cooldown=None):
        self.db = database
        self.cooldown = (
            settings.ALERT_COOLDOWN_SECONDS if cooldown is None else cooldown
        )
        self._last_seen = {}
        self._lock = threading.Lock()

    def raise_alert(self, source, title, risk, details, dedupe_key=None,
                    decision=None):
        """Cree une alerte si le niveau l'exige. Retourne l'id ou None."""
        if risk["level"] == LEVEL_NONE:
            return None

        key = dedupe_key or f"{source}:{title}"
        now = time.monotonic()
        with self._lock:
            last = self._last_seen.get(key)
            if last is not None and now - last < self.cooldown:
                return None
            self._last_seen[key] = now

        payload = dict(details)
        payload["risk"] = risk
        if decision:
            payload["decision"] = decision
        return self.db.add_alert(
            source, title, risk["level"], risk["score"], payload)

    def list(self, **kwargs):
        """Liste les alertes enregistrees."""
        return self.db.list_alerts(**kwargs)

    def acknowledge(self, alert_id):
        """Acquitte une alerte."""
        return self.db.acknowledge_alert(alert_id)

    def stats(self):
        """Compteurs d'alertes par niveau et statut."""
        return self.db.counts()
