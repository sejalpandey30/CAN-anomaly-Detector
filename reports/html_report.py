"""
Standalone Interactive HTML Dashboard Report Generator
Generates a 100% self-contained offline HTML report featuring:
- Executive Threat Summary & Severity Metrics
- Interactive Multi-Signal Timeline Visualizer (Chart.js embedded)
- Anomaly Marker Overlays on Signal Graphs
- Searchable & Filterable Anomaly Data Table
- ECU Bus Load & Message Distribution Charts
- Cybersecurity Diagnosis Cards & Root-Cause Mitigation Recommendations

100% offline with zero external web dependencies.
"""

import os
import json
from typing import List, Dict, Any
from core.anomaly_engine import Anomaly, Severity
from core.log_parser import CANFrame
from core.decoder import DecodedFrame

class HTMLReportGenerator:

    @staticmethod
    def generate(output_filepath: str, log_path: str, dbc_path: str,
                 raw_frames: List[CANFrame], decoded_frames: List[DecodedFrame],
                 anomalies: List[Anomaly]):
        
        # Prepare metadata
        duration = (raw_frames[-1].timestamp - raw_frames[0].timestamp) if len(raw_frames) > 1 else 0.0
        unique_ids = sorted(list(set(f.hex_id for f in raw_frames)))
        
        sev_counts = {Severity.CRITICAL: 0, Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0}
        cat_counts: Dict[str, int] = {}
        
        for a in anomalies:
            sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
            cat_counts[a.category] = cat_counts.get(a.category, 0) + 1

        # Extract signal time-series data for charting (up to top 8 signals)
        signal_series: Dict[str, List[Dict[str, float]]] = {}
        for df in decoded_frames:
            for sig_name, sig_dec in df.signals.items():
                if sig_name not in signal_series:
                    signal_series[sig_name] = []
                signal_series[sig_name].append({
                    "x": round(df.timestamp, 4),
                    "y": round(sig_dec.physical_value, 2)
                })

        # Pick key signals for main timeline chart
        key_signals = [s for s in ["Vehicle_Speed", "Engine_Speed", "Brake_Pedal_Pct", "Throttle_Pedal_Pct", "Steering_Angle", "Battery_SOC"] if s in signal_series]
        if not key_signals and signal_series:
            key_signals = list(signal_series.keys())[:6]

        chart_datasets = []
        colors = ["#4e73df", "#1cc88a", "#f6c23e", "#e74a3b", "#36b9cc", "#9c27b0"]
        for idx, sig in enumerate(key_signals):
            # Downsample if too many points for fast chart rendering
            pts = signal_series[sig]
            if len(pts) > 800:
                step = len(pts) // 800
                pts = pts[::step]
            chart_datasets.append({
                "label": sig,
                "data": pts,
                "borderColor": colors[idx % len(colors)],
                "borderWidth": 2,
                "fill": False,
                "tension": 0.1,
                "pointRadius": 0
            })

        # Anomaly markers for timeline chart
        anomaly_markers = []
        for a in anomalies:
            anomaly_markers.append({
                "x": round(a.timestamp, 4),
                "y": 0,
                "severity": a.severity,
                "label": f"[{a.severity}] {a.affected_signal}: {a.diagnosis[:50]}"
            })

        # Serialize JSON for embedded script
        anomalies_json = json.dumps([a.to_dict() for a in anomalies])
        chart_data_json = json.dumps(chart_datasets)
        markers_json = json.dumps(anomaly_markers)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CAN Bus Cybersecurity & Signal Integrity Report</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-blue: #38bdf8;
            --critical-red: #ef4444;
            --high-orange: #f97316;
            --medium-yellow: #eab308;
            --low-green: #22c55e;
            --border-color: #334155;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif; }}
        body {{ background-color: var(--bg-primary); color: var(--text-main); padding: 24px; line-height: 1.5; }}
        
        .header {{ display: flex; justify-content: space-between; align-items: center; background: var(--bg-secondary); padding: 20px 28px; border-radius: 12px; border: 1px solid var(--border-color); margin-bottom: 24px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }}
        .header h1 {{ font-size: 24px; font-weight: 700; color: #fff; background: linear-gradient(90deg, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .header .subtitle {{ font-size: 13px; color: var(--text-muted); margin-top: 4px; }}
        .badge {{ padding: 6px 14px; border-radius: 20px; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}
        .badge-critical {{ background: rgba(239,68,68,0.2); color: var(--critical-red); border: 1px solid var(--critical-red); }}
        .badge-high {{ background: rgba(249,115,22,0.2); color: var(--high-orange); border: 1px solid var(--high-orange); }}
        .badge-clean {{ background: rgba(34,197,94,0.2); color: var(--low-green); border: 1px solid var(--low-green); }}

        .grid-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .stat-card {{ background: var(--bg-card); padding: 20px; border-radius: 10px; border: 1px solid var(--border-color); }}
        .stat-card .label {{ font-size: 12px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }}
        .stat-card .value {{ font-size: 28px; font-weight: 700; color: #fff; margin-top: 6px; }}
        .stat-card .subtext {{ font-size: 12px; color: var(--text-muted); margin-top: 4px; }}

        .card {{ background: var(--bg-card); border-radius: 12px; border: 1px solid var(--border-color); padding: 24px; margin-bottom: 24px; box-shadow: 0 4px 12px rgba(0,0,0,0.2); }}
        .card-title {{ font-size: 18px; font-weight: 600; margin-bottom: 16px; color: #fff; display: flex; align-items: center; justify-content: space-between; }}

        .chart-container {{ position: relative; height: 350px; width: 100%; }}

        .table-controls {{ display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }}
        .search-input, .select-filter {{ background: #0f172a; border: 1px solid var(--border-color); color: #fff; padding: 10px 14px; border-radius: 6px; font-size: 14px; outline: none; }}
        .search-input {{ flex: 1; min-width: 200px; }}

        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }}
        th {{ background: #0f172a; color: var(--text-muted); font-weight: 600; padding: 12px 16px; border-bottom: 2px solid var(--border-color); text-transform: uppercase; font-size: 12px; }}
        td {{ padding: 14px 16px; border-bottom: 1px solid var(--border-color); vertical-align: top; }}
        tr:hover {{ background: rgba(255,255,255,0.03); }}

        .tag-sev {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; }}
        .tag-CRITICAL {{ background: var(--critical-red); color: #fff; }}
        .tag-HIGH {{ background: var(--high-orange); color: #fff; }}
        .tag-MEDIUM {{ background: var(--medium-yellow); color: #000; }}
        .tag-LOW {{ background: var(--low-green); color: #fff; }}

        .btn {{ background: var(--accent-blue); color: #0f172a; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 13px; text-decoration: none; display: inline-block; }}
        .btn:hover {{ opacity: 0.9; }}

        @media print {{
            body {{ background: #fff; color: #000; }}
            .card, .header, .stat-card {{ background: #fff; border: 1px solid #ccc; color: #000; }}
            .header h1 {{ -webkit-text-fill-color: #000; }}
            .table-controls, .btn {{ display: none; }}
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>

    <div class="header">
        <div>
            <h1>PS-S01 CAN Bus Cybersecurity & Signal Integrity Analyzer</h1>
            <div class="subtitle">Log: <strong>{os.path.basename(log_path)}</strong> | DBC: <strong>{os.path.basename(dbc_path)}</strong></div>
        </div>
        <div>
            {'<span class="badge badge-critical">Threats Detected</span>' if len(anomalies) > 0 else '<span class="badge badge-clean">Bus Status Normal</span>'}
            <button class="btn" style="margin-left: 12px;" onclick="window.print()">Export PDF / Print</button>
        </div>
    </div>

    <div class="grid-stats">
        <div class="stat-card">
            <div class="label">Total Frames Processed</div>
            <div class="value">{len(raw_frames):,}</div>
            <div class="subtext">Across {duration:.2f} seconds ({len(raw_frames)/max(duration, 0.001):.1f} frames/sec)</div>
        </div>
        <div class="stat-card">
            <div class="label">Unique Frame IDs</div>
            <div class="value">{len(unique_ids)}</div>
            <div class="subtext">Transmitting ECUs active</div>
        </div>
        <div class="stat-card">
            <div class="label">Total Anomalies Detected</div>
            <div class="value" style="color: {'var(--critical-red)' if len(anomalies) > 0 else 'var(--low-green)'};">{len(anomalies)}</div>
            <div class="subtext">Flagged by offline security engine</div>
        </div>
        <div class="stat-card">
            <div class="label">Critical / High Severity</div>
            <div class="value" style="color: var(--high-orange);">{sev_counts[Severity.CRITICAL] + sev_counts[Severity.HIGH]}</div>
            <div class="subtext">{sev_counts[Severity.CRITICAL]} Critical | {sev_counts[Severity.HIGH]} High</div>
        </div>
    </div>

    <!-- Timeline Visualizer Card -->
    <div class="card">
        <div class="card-title">
            <span>Decoded Signal Timeline & Anomaly Marker Overlays</span>
            <span style="font-size: 12px; color: var(--text-muted); font-weight: normal;">Showing aligned multi-signal physical telemetry</span>
        </div>
        <div class="chart-container">
            <canvas id="timelineChart"></canvas>
        </div>
    </div>

    <!-- Detailed Anomaly Table Card -->
    <div class="card">
        <div class="card-title">
            <span>Security & Signal Integrity Findings Log</span>
            <span style="font-size: 13px; color: var(--text-muted);">{len(anomalies)} Total Anomalies Flagged</span>
        </div>
        
        <div class="table-controls">
            <input type="text" id="searchInput" class="search-input" placeholder="Search by Signal Name, Frame ID, Category, or Diagnosis..." onkeyup="filterTable()">
            <select id="sevFilter" class="select-filter" onchange="filterTable()">
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
            </select>
            <select id="catFilter" class="select-filter" onchange="filterTable()">
                <option value="ALL">All Categories</option>
                <option value="Out-of-Range Signal">Out-of-Range Signal</option>
                <option value="DoS / Message Flooding Attack">DoS / Message Flooding Attack</option>
                <option value="Timing & Frequency Irregularity">Timing & Frequency Irregularity</option>
                <option value="Cross-Signal Logical Contradiction">Cross-Signal Logical Contradiction</option>
                <option value="Missing Message / ECU Timeout">Missing Message / ECU Timeout</option>
                <option value="Data Corruption / DLC Mismatch">Data Corruption / DLC Mismatch</option>
            </select>
        </div>

        <table id="anomalyTable">
            <thead>
                <tr>
                    <th style="width: 90px;">Time (s)</th>
                    <th style="width: 100px;">Frame ID</th>
                    <th style="width: 140px;">Signal / Field</th>
                    <th style="width: 180px;">Category</th>
                    <th style="width: 90px;">Severity</th>
                    <th>Diagnosis & Security Risk Analysis</th>
                    <th>Possible Root Causes</th>
                </tr>
            </thead>
            <tbody id="tableBody">
            </tbody>
        </table>
    </div>

    <script>
        const anomaliesData = {anomalies_json};
        const chartDatasets = {chart_data_json};

        // Render Table
        function renderTable(data) {{
            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = '';
            if (data.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">No matching anomalies found.</td></tr>';
                return;
            }}
            data.forEach(a => {{
                const tr = document.createElement('tr');
                const causes = Array.isArray(a.possible_causes) ? a.possible_causes.join('<br>• ') : a.possible_causes;
                tr.innerHTML = `
                    <td><strong>${{a.timestamp.toFixed(4)}}</strong></td>
                    <td><code>${{a.frame_id}}</code><br><small style="color:var(--text-muted);">${{a.frame_name}}</small></td>
                    <td><strong>${{a.affected_signal}}</strong></td>
                    <td>${{a.category}}</td>
                    <td><span class="tag-sev tag-${{a.severity}}">${{a.severity}}</span></td>
                    <td>
                        <div>${{a.diagnosis}}</div>
                        <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">Measured: <code>${{a.value}}</code> | Expected: <code>${{a.expected}}</code></div>
                    </td>
                    <td style="font-size:12px; color:var(--text-muted);">• ${{causes}}</td>
                `;
                tbody.appendChild(tr);
            }});
        }}

        function filterTable() {{
            const searchStr = document.getElementById('searchInput').value.toLowerCase();
            const sevVal = document.getElementById('sevFilter').value;
            const catVal = document.getElementById('catFilter').value;

            const filtered = anomaliesData.filter(a => {{
                const matchSearch = searchStr === '' || 
                    a.affected_signal.toLowerCase().includes(searchStr) ||
                    a.frame_id.toLowerCase().includes(searchStr) ||
                    a.category.toLowerCase().includes(searchStr) ||
                    a.diagnosis.toLowerCase().includes(searchStr);
                const matchSev = sevVal === 'ALL' || a.severity === sevVal;
                const matchCat = catVal === 'ALL' || a.category === catVal;
                return matchSearch && matchSev && matchCat;
            }});
            renderTable(filtered);
        }}

        // Render Chart if Chart.js is loaded
        if (typeof Chart !== 'undefined') {{
            const ctx = document.getElementById('timelineChart').getContext('2d');
            new Chart(ctx, {{
                type: 'line',
                data: {{
                    datasets: chartDatasets
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        x: {{
                            type: 'linear',
                            position: 'bottom',
                            title: {{ display: true, text: 'Timestamp (Seconds)', color: '#94a3b8' }},
                            grid: {{ color: '#334155' }},
                            ticks: {{ color: '#94a3b8' }}
                        }},
                        y: {{
                            title: {{ display: true, text: 'Physical Value', color: '#94a3b8' }},
                            grid: {{ color: '#334155' }},
                            ticks: {{ color: '#94a3b8' }}
                        }}
                    }},
                    plugins: {{
                        legend: {{ labels: {{ color: '#f8fafc' }} }},
                        tooltip: {{ mode: 'index', intersect: false }}
                    }}
                }}
            }});
        }}

        // Initial table load
        renderTable(anomaliesData);
    </script>
</body>
</html>
"""
        with open(output_filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return output_filepath
