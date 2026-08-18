# CAN-anomaly-Detector

A Python-based offline automotive cybersecurity and CAN bus analysis platform for decoding controller-area-network traffic, profiling ECU behavior, and detecting anomalies from .dbc-driven signal data.

## Overview

This project parses raw CAN log files, decodes binary payloads using a DBC database, flags suspicious signal behavior, and reports cyber-physical issues such as:

- out-of-range sensor values
- timing-based flooding and message bursts
- cross-signal logical contradictions
- missing message / ECU timeout conditions
- replay or fuzzing-style traffic patterns

It supports local analysis with both a CLI and a Flask web dashboard, and can export HTML, PDF, CSV, and JSON reports.

## Features

- Multi-format CAN parsing for .log, .asc, .trc, and .csv files
- DBC-based decoding with endianness and scaling support
- ECU behavior profiling and traffic fingerprinting
- anomaly detection and threat classification engine
- local web UI at http://127.0.0.1:5000
- output generation for reporting and downstream analysis

## Repository Structure

- `app.py` – Flask dashboard
- `cli.py` – command-line runner
- `core/` – parsing, decoding, profiling, and threat detection logic
- `reports/` – console, HTML, PDF, CSV, and JSON export modules
- `sample_data/` – demo DBC and log files
- `output/` and `output_demo/` – generated reports
- `ui/templates/` – dashboard templates

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the demo analysis

```bash
python cli.py demo
```

### 3. Run a custom file analysis

```bash
python cli.py analyze --dbc sample_data/vehicle_powertrain.dbc --log sample_data/07_master_cyberattack_demo.log --out output
```

### 4. Launch the local dashboard

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Output Formats

The project can generate:

- terminal console summaries
- interactive HTML reports
- PDF technical reports
- CSV telemetry and anomaly logs
- JSON anomaly exports

## Notes

This repository is intended for offline automotive CAN traffic analysis and research. The included sample data is designed to demonstrate the tool's anomaly detection workflow without requiring a live vehicle connection.
