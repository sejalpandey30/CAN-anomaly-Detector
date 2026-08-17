"""
CAN Bus Decoder & Anomaly Detector CLI Entry Point
Offers rich command-line options for running fully offline cybersecurity analysis:

Commands:
  analyze   Run analysis on specified .dbc and .log / .csv files
  demo      Run demonstration on included evaluation dataset

Usage Examples:
  python cli.py analyze --dbc sample_data/vehicle_powertrain.dbc --log sample_data/07_master_cyberattack_demo.log
  python cli.py demo
"""

import sys
import os
import argparse
from typing import List

# Ensure core package is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.dbc_parser import DBCDatabase
from core.log_parser import CANLogParser
from core.anomaly_engine import AnomalyDetector
from reports.console_report import ConsoleReport
from reports.html_report import HTMLReportGenerator
from reports.csv_json_report import Exporter
from reports.pdf_report import PDFReportGenerator

def run_analysis(dbc_path: str, log_path: str, output_dir: str, formats: List[str]):
    print(f"\n[+] Loading DBC Database: {dbc_path}")
    if not os.path.exists(dbc_path):
        print(f"[!] Error: DBC file not found at '{dbc_path}'")
        sys.exit(1)
    dbc = DBCDatabase(dbc_path)
    print(f"    Loaded {len(dbc.frames)} message frame definitions.")

    print(f"[+] Loading CAN Log File: {log_path}")
    if not os.path.exists(log_path):
        print(f"[!] Error: Log file not found at '{log_path}'")
        sys.exit(1)
    raw_frames = CANLogParser.parse_file(log_path)
    print(f"    Parsed {len(raw_frames):,} raw CAN frames.")

    if not raw_frames:
        print("[!] Error: No valid CAN frames could be parsed from log file.")
        sys.exit(1)

    print("[+] Running Cybersecurity & Signal Integrity Detection Engine...")
    detector = AnomalyDetector(dbc)
    decoded_frames, anomalies = detector.analyze_log(raw_frames)
    print(f"    Analysis complete: {len(anomalies)} security anomalies identified.")

    os.makedirs(output_dir, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(log_path))[0]

    # Console Report
    if 'console' in formats or 'all' in formats:
        ConsoleReport.print_to_console(log_path, dbc_path, raw_frames, decoded_frames, anomalies)

    # HTML Report
    if 'html' in formats or 'all' in formats:
        html_out = os.path.join(output_dir, f"{base_name}_report.html")
        HTMLReportGenerator.generate(html_out, log_path, dbc_path, raw_frames, decoded_frames, anomalies)
        html_url = os.path.abspath(html_out).replace("\\", "/")
        print(f"[+] Exported Interactive HTML Report: file:///{html_url}")

    # PDF Report
    if 'pdf' in formats or 'all' in formats:
        pdf_out = os.path.join(output_dir, f"{base_name}_report.pdf")
        out_path = PDFReportGenerator.generate(pdf_out, log_path, dbc_path, raw_frames, decoded_frames, anomalies)
        pdf_url = os.path.abspath(out_path).replace("\\", "/")
        print(f"[+] Exported PDF Report: file:///{pdf_url}")

    # CSV & JSON Reports
    if 'csv' in formats or 'all' in formats:
        csv_out = os.path.join(output_dir, f"{base_name}_anomalies.csv")
        Exporter.export_anomalies_csv(csv_out, anomalies)
        
        telemetry_csv = os.path.join(output_dir, f"{base_name}_decoded_telemetry.csv")
        Exporter.export_decoded_telemetry_csv(telemetry_csv, decoded_frames)
        print(f"[+] Exported CSV Reports: {csv_out} and {telemetry_csv}")

    if 'json' in formats or 'all' in formats:
        json_out = os.path.join(output_dir, f"{base_name}_anomalies.json")
        meta = {"log_file": log_path, "dbc_file": dbc_path, "total_frames": len(raw_frames)}
        Exporter.export_anomalies_json(json_out, anomalies, meta)
        print(f"[+] Exported JSON Report: {json_out}")

    print("\n[OK] Analysis pipeline execution completed successfully.\n")

def main():
    parser = argparse.ArgumentParser(
        description="PS-S01 CAN Bus Data Decoder & Cybersecurity Anomaly Detector (Offline Tool)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Analyze subcommand
    analyze_parser = subparsers.add_parser("analyze", help="Analyze CAN log file using DBC database")
    analyze_parser.add_argument("--dbc", required=True, help="Path to .dbc database file")
    analyze_parser.add_argument("--log", required=True, help="Path to CAN log file (.log, .asc, .trc, .csv)")
    analyze_parser.add_argument("--out", default="output", help="Directory to save generated reports")
    analyze_parser.add_argument("--format", default="all", help="Output formats comma-separated (console,html,pdf,csv,json,all)")

    # Demo subcommand
    demo_parser = subparsers.add_parser("demo", help="Run live judge evaluation test scenario demo")
    demo_parser.add_argument("--out", default="output_demo", help="Directory to save demo reports")

    args = parser.parse_args()

    if args.command == "demo":
        base_dir = os.path.dirname(os.path.abspath(__file__))
        dbc_path = os.path.join(base_dir, "sample_data", "vehicle_powertrain.dbc")
        log_path = os.path.join(base_dir, "sample_data", "07_master_cyberattack_demo.log")
        print("\n" + "="*80)
        print("  RUNNING PS-S01 LIVE JUDGE DEMONSTRATION ON MASTER CYBERATTACK LOG FILE")
        print("="*80)
        run_analysis(dbc_path, log_path, args.out, ["all"])

    elif args.command == "analyze":
        fmts = [f.strip().lower() for f in args.format.split(',')]
        run_analysis(args.dbc, args.log, args.out, fmts)

    else:
        # Default behavior if executed without arguments: run demo
        parser.print_help()

if __name__ == "__main__":
    main()
