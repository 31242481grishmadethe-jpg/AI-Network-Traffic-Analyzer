import os

try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.trained = False
        if HAS_SKLEARN:
            self.model = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100,
            )

    def extract_features(self, flow: dict) -> list:
        return [
            flow.get("packet_count", 0),
            flow.get("bytes_sent", 0) + flow.get("bytes_received", 0),
            flow.get("duration", 0.0),
            flow.get("destination_port", 0) or 0,
            len(str(flow.get("dns_domain", ""))),
        ]

    def train(self, flows: list):
        if not HAS_SKLEARN or not flows:
            return False
        features = [self.extract_features(f) for f in flows]
        X = np.array(features)
        self.model.fit(X)
        self.trained = True
        return True

    def predict(self, flow: dict) -> dict:
        if not HAS_SKLEARN or not self.trained:
            return {"anomaly_score": 0.0, "is_anomaly": False}

        features = np.array([self.extract_features(flow)])
        score = self.model.decision_function(features)[0]
        prediction = self.model.predict(features)[0]

        normalized_score = max(0, min(1.0, 0.5 - score))
        return {
            "anomaly_score": round(normalized_score, 4),
            "is_anomaly": prediction == -1,
        }

    def batch_predict(self, flows: list) -> list:
        if not HAS_SKLEARN or not self.trained:
            return [{"anomaly_score": 0.0, "is_anomaly": False}] * len(flows)

        features = [self.extract_features(f) for f in flows]
        X = np.array(features)
        scores = self.model.decision_function(X)
        predictions = self.model.predict(X)

        results = []
        for score, pred in zip(scores, predictions):
            normalized = max(0, min(1.0, 0.5 - score))
            results.append({
                "anomaly_score": round(normalized, 4),
                "is_anomaly": pred == -1,
            })
        return results
