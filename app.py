"""
CAN Bus Analyzer Web Dashboard Server (Flask Backend)
Provides an interactive web dashboard for offline drag-and-drop log analysis,
signal timeline charting, live playback simulation, custom rule configuration,
and exportable PDF/HTML reports.

100% offline local web app.
"""

import os
import sys
import json
import tempfile
from flask import Flask, render_template, request, jsonify, send_file

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.dbc_parser import DBCDatabase
from core.log_parser import CANLogParser
from core.anomaly_engine import AnomalyDetector, CrossSignalRule, Severity
from reports.html_report import HTMLReportGenerator
from reports.csv_json_report import Exporter

app = Flask(__name__, template_folder="ui/templates", static_folder="ui/static")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_DIR = os.path.join(BASE_DIR, "sample_data")
DEFAULT_DBC = os.path.join(SAMPLE_DIR, "vehicle_powertrain.dbc")
DEFAULT_LOG = os.path.join(SAMPLE_DIR, "07_master_cyberattack_demo.log")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/samples", methods=["GET"])
def get_samples():
    dbc_files = [f for f in os.listdir(SAMPLE_DIR) if f.endswith('.dbc')]
    log_files = [f for f in os.listdir(SAMPLE_DIR) if f.endswith('.log') or f.endswith('.csv') or f.endswith('.trc')]
    return jsonify({
        "dbc_files": sorted(dbc_files),
        "log_files": sorted(log_files)
    })

@app.route("/api/analyze", methods=["POST"])
def analyze_api():
    dbc_file_path = DEFAULT_DBC
    log_file_path = DEFAULT_LOG
    
    temp_dir = tempfile.mkdtemp()

    # Check if files were uploaded via request
    if 'dbc_file' in request.files and request.files['dbc_file'].filename:
        uploaded_dbc = request.files['dbc_file']
        dbc_file_path = os.path.join(temp_dir, uploaded_dbc.filename)
        uploaded_dbc.save(dbc_file_path)
    elif request.form.get('sample_dbc'):
        dbc_file_path = os.path.join(SAMPLE_DIR, request.form.get('sample_dbc'))

    if 'log_file' in request.files and request.files['log_file'].filename:
        uploaded_log = request.files['log_file']
        log_file_path = os.path.join(temp_dir, uploaded_log.filename)
        uploaded_log.save(log_file_path)
    elif request.form.get('sample_log'):
        log_file_path = os.path.join(SAMPLE_DIR, request.form.get('sample_log'))

    if not os.path.exists(dbc_file_path) or not os.path.exists(log_file_path):
        return jsonify({"error": "DBC or Log file not found"}), 400

    # Parse and analyze
    try:
        dbc = DBCDatabase(dbc_file_path)
        raw_frames = CANLogParser.parse_file(log_file_path)
        detector = AnomalyDetector(dbc)
        decoded_frames, anomalies = detector.analyze_log(raw_frames)

        duration = (raw_frames[-1].timestamp - raw_frames[0].timestamp) if len(raw_frames) > 1 else 0.0
        unique_ids = list(set(f.hex_id for f in raw_frames))

        # Build signal time series dictionary for dashboard plots
        signal_series = {}
        for df in decoded_frames:
            for sig_name, sig_dec in df.signals.items():
                if sig_name not in signal_series:
                    signal_series[sig_name] = []
                signal_series[sig_name].append({
                    "x": round(df.timestamp, 4),
                    "y": round(sig_dec.physical_value, 2)
                })

        # Bus load frame rate over 0.1s bins
        bus_load_bins = {}
        for f in raw_frames:
            bin_idx = round(f.timestamp, 1)
            bus_load_bins[bin_idx] = bus_load_bins.get(bin_idx, 0) + 1

        bus_load_pts = [{"x": k, "y": v} for k, v in sorted(bus_load_bins.items())]

        return jsonify({
            "success": True,
            "metadata": {
                "dbc_name": os.path.basename(dbc_file_path),
                "log_name": os.path.basename(log_file_path),
                "total_frames": len(raw_frames),
                "duration_seconds": round(duration, 2),
                "unique_ids_count": len(unique_ids),
                "unique_ids": sorted(unique_ids),
                "anomaly_count": len(anomalies)
            },
            "anomalies": [a.to_dict() for a in anomalies],
            "signal_series": signal_series,
            "bus_load_series": bus_load_pts
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = 5000
    print(f"\n[+] Launching CAN Bus Analyzer Web Dashboard at: http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
