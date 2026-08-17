# CAN-anomaly-Detector

This branch adds a core offline CAN anomaly detection tool with parsing, DBC decoding, anomaly detection, and reporting.

Quick start

1. Create a Python virtual environment and install dependencies:

   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt

2. Run the analyzer (replace examples/sample.dbc with a real DBC):

   python -m can_anom.main --dbc examples/sample.dbc --log examples/sample_log.csv --out demo_report

Files added
- can_anom/ : core modules (main, parser, decoder, detector, reporter, viz)
- configs/rules.yaml : example logical rules
- examples/ : sample log and placeholder DBC
- requirements.txt

Notes
- The provided sample.dbc is only a placeholder. Replace it with the real .dbc file for correct decoding.
- This is the initial implementation covering mandatory requirements (out-of-range, timing, logic rules) and basic reporting. Follow-up improvements (missing message detection, CRC checks, improved parsers, packaging) can be added.
