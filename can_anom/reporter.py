import json
import csv
from datetime import datetime
from jinja2 import Template

HTML_TMPL = """
<html><head><meta charset="utf-8"><title>CAN Anomaly Report</title></head>
<body>
<h1>CAN Anomaly Report</h1>
<p>Generated: {{generated}}</p>
<table border="1" cellpadding="4">
<tr><th>timestamp</th><th>severity</th><th>type</th><th>message</th><th>msg_id</th><th>signal</th></tr>
{% for a in anomalies %}
<tr>
  <td>{{a.timestamp}}</td>
  <td>{{a.severity}}</td>
  <td>{{a.type}}</td>
  <td>{{a.message}}</td>
  <td>{{a.message_id}}</td>
  <td>{{a.signal or ''}}</td>
</tr>
{% endfor %}
</table>
</body></html>
"""

class Reporter:
    def to_json(self, anomalies, path):
        with open(path, "w") as f:
            json.dump(anomalies, f, indent=2, default=str)

    def to_csv(self, anomalies, path):
        keys = ["timestamp","severity","type","message","message_id","signal"]
        with open(path, "w", newline='') as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            for a in anomalies:
                row = {k: a.get(k,"") for k in keys}
                w.writerow(row)

    def to_html(self, anomalies, path, embed_plots=False, detector=None):
        t = Template(HTML_TMPL)
        html = t.render(generated=str(datetime.utcnow()), anomalies=anomalies)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
