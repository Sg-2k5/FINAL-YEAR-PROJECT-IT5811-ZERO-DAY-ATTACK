"""
Alert Logger — Exports detection results and alerts to JSON & CSV
=================================================================
"""

import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Optional

from src.data.schemas import DetectionResult, Alert


def _to_native(val):
    """Convert numpy types to native Python types."""
    if hasattr(val, "item"):
        return val.item()
    return val


class AlertLogger:
    """Saves anomaly detection results and alerts to files for later analysis."""

    def __init__(self, output_dir: str = "logs"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ── JSON export ────────────────────────────────────────────
    def save_results_json(self, results: List[DetectionResult], alerts: List[Alert], extra: Optional[Dict] = None):
        """Save full detection session to a JSON file."""
        path = os.path.join(self.output_dir, f"detection_{self.session_id}.json")

        data = {
            "session_id": self.session_id,
            "timestamp": datetime.now().isoformat(),
            "total_graphs": len(results),
            "total_anomalies": sum(1 for r in results if r.is_anomalous),
            "results": [
                {
                    "graph_id": r.graph_id,
                    "anomaly_score": round(float(r.anomaly_score), 6),
                    "threshold": round(float(r.threshold), 6),
                    "is_anomalous": bool(r.is_anomalous),
                    "timestamp": int(r.timestamp),
                }
                for r in results
            ],
            "alerts": [
                {
                    "alert_id": a.alert_id,
                    "graph_id": a.graph_id,
                    "severity": a.severity,
                    "anomaly_score": round(float(a.anomaly_score), 6),
                    "timestamp": int(a.timestamp),
                    "description": a.description,
                }
                for a in alerts
            ],
        }
        if extra:
            data["extra"] = {k: _to_native(v) for k, v in extra.items()}

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        return path

    # ── CSV export ─────────────────────────────────────────────
    def save_results_csv(self, results: List[DetectionResult], extra: Optional[Dict] = None):
        """Save detection results to a CSV file."""
        path = os.path.join(self.output_dir, f"detection_{self.session_id}.csv")

        base_headers = ["graph_id", "anomaly_score", "threshold", "is_anomalous", "timestamp"]
        extra_headers = list(extra.keys()) if extra else []

        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(base_headers + extra_headers)
            for r in results:
                row = [r.graph_id, round(float(r.anomaly_score), 6), round(float(r.threshold), 6), bool(r.is_anomalous), int(r.timestamp)]
                if extra:
                    row.extend([_to_native(extra[k]) for k in extra_headers])
                writer.writerow(row)

        return path

    # ── Append single alert (for continuous mode) ──────────────
    def append_alert(self, alert: Alert):
        """Append a single alert to a running log file."""
        path = os.path.join(self.output_dir, f"alerts_live_{self.session_id}.jsonl")
        with open(path, "a") as f:
            entry = {
                "alert_id": alert.alert_id,
                "graph_id": alert.graph_id,
                "severity": alert.severity,
                "anomaly_score": round(alert.anomaly_score, 6),
                "timestamp": alert.timestamp,
                "description": alert.description,
                "logged_at": datetime.now().isoformat(),
            }
            f.write(json.dumps(entry) + "\n")
        return path
