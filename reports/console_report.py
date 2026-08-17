"""
Console Tabular Report Generator
Renders a rich, colored, readable terminal report summarizing:
- Analysis Metadata (Log File, DBC File, Total Frames, Time Duration)
- Cybersecurity Anomaly Summary & Severity Breakdown (CRITICAL, HIGH, MEDIUM, LOW)
- Category Distribution Table
- Detailed Anomaly Findings Log (Timestamp, ID, Signal, Category, Severity, Diagnosis, Possible Causes)

100% offline, pure-Python implementation.
"""

import os
from typing import List, Dict, Any
from core.anomaly_engine import Anomaly, Severity, AnomalyCategory
from core.log_parser import CANFrame
from core.decoder import DecodedFrame

class ConsoleReport:

    @staticmethod
    def render(log_path: str, dbc_path: str, raw_frames: List[CANFrame],
               decoded_frames: List[DecodedFrame], anomalies: List[Anomaly], max_details: int = 25) -> str:
        lines = []

        def add_line(text=""):
            lines.append(text)

        sep_double = "=" * 88
        sep_single = "-" * 88

        # Title Banner
        add_line(sep_double)
        add_line("   AUTOMOTIVE CAN BUS DATA DECODER & CYBERSECURITY ANOMALY DETECTOR")
        add_line("   PC-Based Offline Signal Integrity & Threat Analysis Report")
        add_line(sep_double)

        # Metadata Section
        duration = (raw_frames[-1].timestamp - raw_frames[0].timestamp) if len(raw_frames) > 1 else 0.0
        unique_ids = len(set(f.frame_id for f in raw_frames))
        
        add_line(f" LOG FILE    : {os.path.basename(log_path)}")
        add_line(f" DBC DATABASE: {os.path.basename(dbc_path)}")
        add_line(f" TOTAL FRAMES: {len(raw_frames):,} frames decoded over {duration:.2f} seconds")
        add_line(f" UNIQUE IDs  : {unique_ids} CAN frame IDs detected")
        add_line(f" ANOMALIES   : {len(anomalies)} security & integrity issues flagged")
        add_line(sep_single)

        # Severity Breakdown Table
        sev_counts = {Severity.CRITICAL: 0, Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0}
        cat_counts: Dict[str, int] = {}

        for a in anomalies:
            sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
            cat_counts[a.category] = cat_counts.get(a.category, 0) + 1

        add_line(" [1] SEVERITY LEVEL DISTRIBUTION")
        add_line(f"     CRITICAL : {sev_counts[Severity.CRITICAL]:>4}  (Immediate vehicle safety / motion hazard)")
        add_line(f"     HIGH     : {sev_counts[Severity.HIGH]:>4}  (ECU fault / out-of-range spoofing / flooding)")
        add_line(f"     MEDIUM   : {sev_counts[Severity.MEDIUM]:>4}  (Timing jitter / minor range boundary violation)")
        add_line(f"     LOW      : {sev_counts[Severity.LOW]:>4}  (Informational warning)")
        add_line(sep_single)

        # Category Breakdown Table
        add_line(" [2] ANOMALY CATEGORY SUMMARY")
        add_line(f"   {'Category Name':<38} | {'Count':<8} | {'Ratio':<8}")
        add_line("   " + "-" * 60)
        total_anom = len(anomalies) if anomalies else 1
        for cat, cnt in cat_counts.items():
            pct = (cnt / total_anom) * 100
            add_line(f"   {cat:<38} | {cnt:<8} | {pct:>6.1f}%")
        add_line(sep_single)

        # Detailed Findings Table
        add_line(" [3] DETAILED ANOMALY FINDINGS TRACE")
        if not anomalies:
            add_line("   >>> CLEAN BUS TRACE: No cybersecurity anomalies or signal integrity defects detected.")
        else:
            add_line(f"   Showing top {min(len(anomalies), max_details)} of {len(anomalies)} anomalies:")
            add_line("")
            for idx, a in enumerate(anomalies[:max_details], 1):
                add_line(f"   #{idx:02d} [{a.severity:<8}] t={a.timestamp:09.4f}s | Frame {a.hex_id} ({a.frame_name}) | Sig: {a.affected_signal}")
                add_line(f"        Category : {a.category}")
                add_line(f"        Diagnosis: {a.diagnosis}")
                add_line(f"        Val/Exp  : Measured={a.value} | Expected={a.expected}")
                if a.possible_causes:
                    add_line(f"        Causes   : {'; '.join(a.possible_causes[:2])}")
                add_line("   " + "." * 84)

        if len(anomalies) > max_details:
            add_line(f"   ... and {len(anomalies) - max_details} additional anomalies omitted from console view.")

        add_line(sep_double)
        report_str = "\n".join(lines)
        return report_str

    @staticmethod
    def print_to_console(log_path: str, dbc_path: str, raw_frames: List[CANFrame],
                         decoded_frames: List[DecodedFrame], anomalies: List[Anomaly]):
        text = ConsoleReport.render(log_path, dbc_path, raw_frames, decoded_frames, anomalies)
        print(text)
