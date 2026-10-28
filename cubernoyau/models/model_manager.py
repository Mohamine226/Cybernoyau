"""Modele d'anomalies de processus (Isolation Forest) avec base de reference.

Le modele est reentraine a chaque cycle sur : les mesures recentes
(reference) + l'instantane courant. Les processus signales ne sont pas
ajoutes a la reference, pour ne pas apprendre une attaque comme normale.
"""

from collections import deque

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from cubernoyau.models.anomaly_detector import FEATURE_COLUMNS


class ProcessAnomalyModel:
    """Isolation Forest : detecte les processus statistiquement inhabituels parmi ceux observes."""
    def __init__(self, contamination=0.03, max_baseline=2000,
                 min_samples=10, random_state=42):
        self.contamination = contamination
        self.min_samples = min_samples
        self.random_state = random_state
        self._baseline = deque(maxlen=max_baseline)

    @staticmethod
    def _matrix(features):
        return np.array(
            [[float(row.get(c, 0) or 0) for c in FEATURE_COLUMNS]
             for row in features],
            dtype=float,
        )

    def score(self, features):
        """Retourne une liste [{anomaly, score}] alignee sur `features`.
        Liste de None si l'echantillon est trop petit."""
        if len(features) < self.min_samples:
            return [None] * len(features)

        current = self._matrix(features)
        train = (np.vstack([np.array(self._baseline), current])
                 if self._baseline else current)

        pipeline = make_pipeline(
            SimpleImputer(strategy="median"),
            StandardScaler(),
            IsolationForest(n_estimators=150,
                            contamination=self.contamination,
                            random_state=self.random_state),
        )
        pipeline.fit(train)
        transformed = pipeline[:-1].transform(current)
        forest = pipeline.named_steps["isolationforest"]
        flags = forest.predict(transformed)
        scores = forest.decision_function(transformed)

        results = []
        for row, flag, value in zip(current, flags, scores):
            anomaly = bool(flag == -1)
            if not anomaly:
                self._baseline.append(row)
            results.append({"anomaly": anomaly, "score": round(float(value), 4)})
        return results
