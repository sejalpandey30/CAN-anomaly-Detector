# CAN-anomaly-Detector — Offline CAN Bus Anomaly Detector (demo branch)

This repository contains a local, offline tool to analyze pre-recorded CAN bus logs, decode them using a .dbc file, and detect anomalies such as out-of-range signal values, message timing irregularities, logical contradictions across signals, and optional checks like missing messages and flooding.

## Quick summary
- Decodes raw CAN frames using a provided .dbc (Database CAN) file (using cantools).
- Detects mandatory anomaly types: out-of-range signals, timing irregularities, logical contradictions.
- Optionally detects missing messages (timeouts) and flooding (bus overload/replay).
- Produces JSON, CSV, and a simple HTML report. Optional PNG plots can be generated for signal timelines.

## Quick start (copy/paste)
Follow these steps to run the analyzer locally.

### macOS / Linux
1) Clone and switch to the demo branch:

   git clone https://github.com/sejalpandey30/CAN-anomaly-Detector.git
   cd CAN-anomaly-Detector
   git fetch origin enhancement/core-analyzer
   git checkout enhancement/core-analyzer

2) Create and activate a Python virtual environment:

   python3 -m venv venv
   source venv/bin/activate

3) Install dependencies:

   python -m pip install --upgrade pip
   pip install -r requirements.txt

4) Run the unit tests (quick smoke tests):

   pytest -q

5) Run the analyzer (example using the included sample files):

   python -m can_anom.main --dbc examples/sample.dbc --log examples/sample_log.csv --rules configs/rules.yaml --out demo_report --timing-threshold 0.3

6) Open the generated report files (in repository root):

   - demo_report.json  — structured anomalies (machine friendly)
   - demo_report.csv   — table format (spreadsheet friendly)
   - demo_report.html  — human readable table (open in a browser)

### Windows (PowerShell)
1) Clone & branch:

   git clone https://github.com/sejalpandey30/CAN-anomaly-Detector.git
   cd CAN-anomaly-Detector
   git fetch origin enhancement/core-analyzer
   git checkout enhancement/core-analyzer

2) Virtual environment:

   python -m venv venv
   .\venv\Scripts\Activate.ps1

3) Install dependencies:

   python -m pip install --upgrade pip
   pip install -r requirements.txt

4) Tests:

   pytest -q

5) Run analyzer:

   python -m can_anom.main --dbc examples\sample.dbc --log examples\sample_log.csv --rules configs\rules.yaml --out demo_report --timing-threshold 0.3

## Command-line interface (what each option means)
- --dbc PATH
  Path to the .dbc Database CAN file used to decode frames into signals.

- --log PATH
  Path to the CAN log file. The parser accepts CSV exports with headers (timestamp, id, data) or simple space-delimited lines: timestamp id data.

- --rules PATH (optional)
  YAML rules file that encodes cross-signal logical checks (see configs/rules.yaml).

- --out BASENAME
  Base name used for outputs. The tool creates BASENAME.json, BASENAME.csv, and BASENAME.html.

- --plot (optional)
  Generate signal timeline plots (PNG files) and embed them into the HTML report (basic support).

- --timing-threshold FLOAT
  Relative tolerance for timing anomalies: how much the observed inter-message interval may deviate from the nominal before being flagged (default 0.3 = 30%).

## What the tool outputs
- JSON: Full anomaly records (timestamp, type, severity, message, message_id, signal, possible_causes).
- CSV: Tabular summary suitable for spreadsheets.
- HTML: Simple, easy-to-open report in your browser.

## Anomaly types (brief)
- out_of_range: Signal value outside the DBC-defined min/max.
- timing: Inter-message interval deviates from nominal by more than --timing-threshold.
- logic: Rule engine found a contradiction (e.g., speed > 0 and EngineOn == 0).
- missing: Gap between messages greater than a configurable multiplier of nominal.
- flood: Many messages arrive at rates much faster than nominal (possible replay/flood).

## Repository structure (simple explanations)
- can_anom/ — main Python package
  - main.py    — CLI orchestration (parsing → decoding → detection → reporting)
  - parser.py  — permissive streaming parser for CSV and simple log formats
  - decoder.py — loads .dbc using cantools and decodes frames
  - detector.py — implements detection logic (out-of-range, timing, missing, flood, rule engine)
  - reporter.py — writes JSON, CSV, and a simple HTML report (uses Jinja2)
  - viz.py      — helper for generating simple signal plots (matplotlib)

- configs/
  - rules.yaml — example rule(s) showing how to define logical contradictions

- examples/
  - sample_log.csv — minimal example log (for smoke tests)
  - sample.dbc     — placeholder DBC (replace with your real .dbc)

- tests/
  - test_parser.py   — parser smoke test
  - test_detector.py — tests for detector logic (out_of_range, timing, logic)

- .github/workflows/
  - python-tests.yml — CI: runs pytest on push/pull requests (present on branch)

- requirements.txt — packages required to run (cantools, jinja2, pyyaml, matplotlib, ...)

## Configure logical rules (configs/rules.yaml)
Rules are YAML objects describing which signals to check together and the condition that constitutes a logical anomaly.

Example rule:

- name: speed_impossible_with_engine_off
  description: "Vehicle speed > 0 while EngineRunning == 0"
  when:
    - message_id: 0x200
      signal: VehicleSpeed
    - message_id: 0x201
      signal: EngineRunning
  condition: "VehicleSpeed > 0 and EngineRunning == 0"
  severity: High
  possible_causes:
    - "sensor stuck"
    - "replay attack"

Notes:
- The detector looks for signals from the specified message IDs within a small time window (default ~10 ms). Adjust the window in can_anom/detector.py if your signals are less tightly synchronized.
- For safety in production, consider replacing the rule-eval `eval()` with a safe expression evaluator.

## Tuning detection behavior
- Timing threshold: use --timing-threshold on the CLI.
- Missing message multiplier, flood ratio, and flood count: configurable in can_anom/detector.py constructor (defaults are reasonable for demos).

## Troubleshooting
- If cantools fails to decode, ensure your .dbc matches the frames and signals in the log.
- If no anomalies show up, check units and timestamp scales (seconds vs microseconds).
- To parse vendor formats (Vector/PEAK/SocketCAN), either export to CSV first or ask to add a vendor parser.

## Next improvements (suggestions)
- Add vendor-specific log readers (python-can integration).
- Improve rule safety (replace eval with a proper expression parser).
- Enhance the HTML report with charts and interactive filtering.
- Package as a single-file executable with pyinstaller for offline demos.

## Contributing & testing
Run the test suite locally:

python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest -q

CI automatically runs tests when a PR is opened against this repository (see .github/workflows).


