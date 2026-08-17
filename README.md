# CAN-anomaly-Detector — Offline CAN Bus Anomaly Detector (demo branch)

A compact, offline tool to analyze pre-recorded CAN bus logs, decode signals using a .dbc file, and flag anomalies (out-of-range values, timing irregularities, logical contradictions). Produces JSON/CSV/HTML reports and optional PNG plots.

Quick start (short)

Linux / macOS (copy/paste):

1) Clone & checkout demo branch

   git clone https://github.com/sejalpandey30/CAN-anomaly-Detector.git
   cd CAN-anomaly-Detector
   git fetch origin enhancement/core-analyzer
   git checkout enhancement/core-analyzer

2) Create venv & install

   python3 -m venv venv
   source venv/bin/activate
   python -m pip install --upgrade pip
   pip install -r requirements.txt

3) Run tests and analyzer

   pytest -q
   python -m can_anom.main --dbc examples/sample.dbc --log examples/sample_log.csv --rules configs/rules.yaml --out demo_report --timing-threshold 0.3

4) Open report files:

   - demo_report.json  — structured anomalies
   - demo_report.csv   — table for spreadsheets
   - demo_report.html  — open in a browser

Windows (PowerShell) quick copy/paste

   git clone https://github.com/sejalpandey30/CAN-anomaly-Detector.git
   cd CAN-anomaly-Detector
   git fetch origin enhancement/core-analyzer
   git checkout enhancement/core-analyzer
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   pytest -q
   python -m can_anom.main --dbc examples\sample.dbc --log examples\sample_log.csv --rules configs\rules.yaml --out demo_report --timing-threshold 0.3

Or, Windows Batch (cmd.exe):

   python -m venv venv
   venv\Scripts\activate.bat
   python -m pip install -r requirements.txt
   python -m can_anom.main --dbc examples\sample.dbc --log examples\sample_log.csv --rules configs\rules.yaml --out demo_report

What the CLI options do (one-line each)

- --dbc PATH: .dbc file to decode frames
- --log PATH: CSV or simple space-delimited CAN log (timestamp,id,data)
- --rules PATH: YAML file with logical-contradiction rules
- --out BASENAME: output files BASENAME.json / .csv / .html
- --plot: create PNG signal plots and embed in HTML
- --timing-threshold FLOAT: relative timing tolerance (default 0.3)

Example output snippet (demo_report.json)

[
  {
    "timestamp": 0.1,
    "type": "timing",
    "message": "Interval 0.100000s dev from nominal 0.075250s",
    "severity": "Medium",
    "message_id": 512,
    "signal": null
  }
]

And demo_report.csv (first line):

timestamp,severity,type,message,message_id,signal
0.1,Medium,timing,"Interval 0.100000s dev from nominal 0.075250s",512,

Screenshot placeholder

- Take a screenshot of demo_report.html open in a browser and place it in docs/report_screenshot.png. I left a placeholder in the README where the image can be embedded.

Repository highlights (short)

- can_anom/: core code (main.py, parser.py, decoder.py, detector.py, reporter.py, viz.py)
- configs/rules.yaml: example rule(s)
- examples/: sample log + placeholder .dbc
- tests/: pytest smoke tests
- .github/workflows/: CI workflow (runs pytest)

Rules quick example (configs/rules.yaml)

- name: speed_impossible_with_engine_off
  description: "Vehicle speed > 0 while EngineRunning == 0"
  when:
    - message_id: 0x200
      signal: VehicleSpeed
    - message_id: 0x201
      signal: EngineRunning
  condition: "VehicleSpeed > 0 and EngineRunning == 0"

Tips & troubleshooting (quick)

- Replace examples/sample.dbc with your real DBC for correct decoding and min/max checks.
- If timestamps are large integers (microseconds), convert to seconds or update parser.py.
- For vendor logs (Vector/PEAK/SocketCAN), export to CSV or ask to add a specific parser.

Want me to:
- Add the screenshot placeholder file (I can generate a sample if you run the tool or permit a GitHub Action to run it),
- Or open a PR to merge this branch into your default branch?

