import yaml
from collections import defaultdict
import statistics

class Detector:
    def __init__(self, decoder, timing_threshold=0.3, rules_path=None):
        self.decoder = decoder
        self.timing_threshold = timing_threshold
        # last timestamp per message id
        self.last_ts = {}
        self.intervals = defaultdict(list)
        self.anomalies = []
        self.signal_history = defaultdict(list)  # msgid -> list of (ts, decoded dict)
        self.rules = []
        if rules_path:
            try:
                with open(rules_path, 'r') as f:
                    self.rules = yaml.safe_load(f) or []
            except Exception:
                self.rules = []

    def _severity(self, typ):
        # simple mapping; refine later
        return {"out_of_range":"High", "timing":"Medium", "logic":"High", "missing":"High"}.get(typ, "Low")

    def process_frame(self, ts, can_id, data_bytes):
        decoded = self.decoder.decode(can_id, data_bytes)
        # store raw decoded
        self.signal_history[can_id].append((ts, decoded))
        # check out-of-range per signal (if decoder provides limits)
        if decoded:
            msg = self.decoder.msg_by_id.get(can_id)
            for signame, val in decoded.items():
                sig = None
                try:
                    sig = next((s for s in (msg.signals if msg else []) if s.name==signame), None)
                except Exception:
                    sig = None
                if sig and (getattr(sig, 'minimum', None) is not None or getattr(sig, 'maximum', None) is not None):
                    try:
                        if getattr(sig, 'minimum', None) is not None and val < sig.minimum:
                            self.anomalies.append(self._mk_anomaly(ts, "out_of_range",
                                                                   f"{signame} low: {val} < {sig.minimum}",
                                                                   can_id, signame))
                        if getattr(sig, 'maximum', None) is not None and val > sig.maximum:
                            self.anomalies.append(self._mk_anomaly(ts, "out_of_range",
                                                                   f"{signame} high: {val} > {sig.maximum}",
                                                                   can_id, signame))
                    except Exception:
                        pass
        # timing
        if can_id in self.last_ts:
            delta = ts - self.last_ts[can_id]
            if delta >= 0:
                self.intervals[can_id].append(delta)
                nominal = self._nominal_period(can_id)
                if nominal is not None and nominal > 0:
                    if abs(delta - nominal) / nominal > self.timing_threshold:
                        self.anomalies.append(self._mk_anomaly(ts, "timing",
                                                               f"Interval {delta:.6f}s dev from nominal {nominal:.6f}s",
                                                               can_id, None))
        self.last_ts[can_id] = ts

        # simple logical checks: evaluate per-timestamp across signals
        self._evaluate_rules(ts, can_id, decoded)

    def _nominal_period(self, can_id):
        ints = self.intervals.get(can_id, [])
        if not ints:
            return None
        # robust estimate: median
        return statistics.median(ints)

    def _evaluate_rules(self, ts, can_id, decoded):
        # simple window to find signals at same time
        window = 0.01  # 10 ms
        for r in self.rules:
            involved = {}
            ok = True
            for clause in r.get("when", []):
                mid = clause["message_id"]
                sig = clause["signal"]
                vals = self.signal_history.get(mid, [])
                found = None
                for t, d in reversed(vals):
                    if abs(t - ts) <= window:
                        if d and sig in d:
                            found = d[sig]
                            break
                if found is None:
                    ok = False
                    break
                involved[sig] = found
            if not ok:
                continue
            try:
                local_vars = {k: v for k, v in involved.items()}
                if eval(r["condition"], {"__builtins__": {}}, local_vars):
                    self.anomalies.append({
                        "timestamp": ts,
                        "type": "logic",
                        "message": r.get("description", r.get("name", "rule_triggered")),
                        "severity": r.get("severity", self._severity("logic")),
                        "message_id": can_id,
                        "details": involved,
                        "possible_causes": r.get("possible_causes", [])
                    })
            except Exception:
                continue

    def _mk_anomaly(self, ts, typ, msg, can_id, signame):
        return {
            "timestamp": ts,
            "type": typ,
            "message": msg,
            "severity": self._severity(typ),
            "message_id": can_id,
            "signal": signame,
            "possible_causes": []
        }

    def finalize(self):
        # placeholder for missing-message detection and post-processing
        return self.anomalies
