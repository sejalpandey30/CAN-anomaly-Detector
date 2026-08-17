"""
CSV and JSON Report Exporter Module
Exports decoded frames, signal telemetry, and detected cybersecurity anomalies into:
- Structured JSON format (for SIEM, SOC, and automated pipeline integration)
- Standard CSV format (for Excel, pandas, and data processing)

100% offline, pure-Python implementation.
"""

import csv
import json
from typing import List, Dict, Any
from core.anomaly_engine import Anomaly
from core.decoder import DecodedFrame

class Exporter:

    @staticmethod
    def export_anomalies_json(filepath: str, anomalies: List[Anomaly], metadata: Dict[str, Any]):
        data = {
            "metadata": metadata,
            "summary": {
                "total_anomalies": len(anomalies),
                "severity_counts": {
                    "CRITICAL": sum(1 for a in anomalies if a.severity == "CRITICAL"),
                    "HIGH": sum(1 for a in anomalies if a.severity == "HIGH"),
                    "MEDIUM": sum(1 for a in anomalies if a.severity == "MEDIUM"),
                    "LOW": sum(1 for a in anomalies if a.severity == "LOW"),
                }
            },
            "anomalies": [a.to_dict() for a in anomalies]
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        return filepath

    @staticmethod
    def export_anomalies_csv(filepath: str, anomalies: List[Anomaly]):
        fieldnames = [
            "timestamp", "frame_id", "frame_name", "affected_signal",
            "category", "severity", "diagnosis", "value", "expected", "possible_causes"
        ]
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for a in anomalies:
                row = a.to_dict()
                row["possible_causes"] = " | ".join(a.possible_causes)
                writer.writerow(row)
        return filepath

    @staticmethod
    def export_decoded_telemetry_csv(filepath: str, decoded_frames: List[DecodedFrame]):
        """Exports all decoded physical signals as a flat tabular time-series CSV."""
        if not decoded_frames:
            return filepath

        # Collect all unique signal names across frames
        all_signal_names = set()
        for df in decoded_frames:
            all_signal_names.update(df.signals.keys())
        sorted_signals = sorted(list(all_signal_names))

        fieldnames = ["timestamp", "frame_id", "frame_name"] + sorted_signals

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for df in decoded_frames:
                row = {
                    "timestamp": f"{df.timestamp:.6f}",
                    "frame_id": df.hex_id,
                    "frame_name": df.frame_name
                }
                for sig in sorted_signals:
                    if sig in df.signals:
                        row[sig] = f"{df.signals[sig].physical_value:.3f}"
                    else:
                        row[sig] = ""
                writer.writerow(row)
        return filepath
