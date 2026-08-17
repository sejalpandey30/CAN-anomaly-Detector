#!/usr/bin/env python3
import argparse
from pathlib import Path
from can_anom.decoder import DBCDecoder
from can_anom.parser import LogParser
from can_anom.detector import Detector
from can_anom.reporter import Reporter


def build_cli():
    p = argparse.ArgumentParser(description="Offline CAN Bus Anomaly Detector")
    p.add_argument("--dbc", required=True, help="Path to DBC file")
    p.add_argument("--log", required=True, help="Path to CAN log (.csv or .log-export)")
    p.add_argument("--rules", help="Logical rules YAML (optional)")
    p.add_argument("--out", default="report", help="Output basename (report.json/report.csv/report.html)")
    p.add_argument("--plot", action="store_true", help="Generate plot images and embed in HTML")
    p.add_argument("--timing-threshold", type=float, default=0.3,
                   help="Relative deviation threshold for timing anomalies (default 0.3 = 30%%)")
    return p


def main():
    args = build_cli().parse_args()
    dbc_path = Path(args.dbc)
    log_path = Path(args.log)

    decoder = DBCDecoder(dbc_path)
    parser = LogParser(log_path)
    detector = Detector(decoder, timing_threshold=args.timing_threshold, rules_path=args.rules)
    reporter = Reporter()

    print("Starting parse & decode...")
    for ts, can_id, data_bytes in parser:
        detector.process_frame(ts, can_id, data_bytes)

    print("Finalizing detection...")
    anomalies = detector.finalize()

    print(f"Detected {len(anomalies)} anomalies")
    # console summary
    for a in anomalies[:50]:
        print(f"{a.get('timestamp')} | {a.get('severity')} | {a.get('type')} | {a.get('message')}")

    # write reports
    reporter.to_json(anomalies, args.out + ".json")
    reporter.to_csv(anomalies, args.out + ".csv")
    reporter.to_html(anomalies, args.out + ".html", embed_plots=args.plot, detector=detector)
    print("Reports written:", args.out + ".{json,csv,html}")


if __name__ == "__main__":
    main()
