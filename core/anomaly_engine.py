"""
Automotive Cybersecurity & Signal Integrity Anomaly Detection Engine
Implements mandatory & optional cybersecurity anomaly detection rules:
1. Out-of-Range Signal Values (Mandatory)
2. Message Timing & Frequency Irregularities / DoS Flooding / Replay (Mandatory)
3. Cross-Signal Logical Contradiction Engine (Mandatory)
4. Missing Messages / ECU Signal Timeout (Optional - High Credit)
5. Data Corruption & DLC Mismatch / Counter Sequence Errors (Optional - High Credit)

100% offline, pure-Python implementation.
"""

from typing import List, Dict, Optional, Any, Tuple
import math
from core.dbc_parser import DBCDatabase, Frame, Signal
from core.log_parser import CANFrame
from core.decoder import CANDecoder, DecodedFrame, DecodedSignal

class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class AnomalyCategory:
    OUT_OF_RANGE = "Out-of-Range Signal"
    TIMING_IRREGULARITY = "Timing & Frequency Irregularity"
    DOS_FLOODING = "DoS / Message Flooding Attack"
    LOGICAL_CONTRADICTION = "Cross-Signal Logical Contradiction"
    ECU_TIMEOUT = "Missing Message / ECU Timeout"
    DATA_CORRUPTION = "Data Corruption / DLC Mismatch"
    SEQUENCE_ERROR = "Counter / Sequence Error"

class Anomaly:
    """Represents a detected cybersecurity or signal integrity anomaly."""
    def __init__(self, timestamp: float, frame_id: int, frame_name: str,
                 affected_signal: str, category: str, severity: str,
                 diagnosis: str, possible_causes: List[str],
                 raw_frame: Optional[CANFrame] = None,
                 value: Optional[Any] = None, expected: Optional[Any] = None):
        self.timestamp = timestamp
        self.frame_id = frame_id
        self.hex_id = f"0x{frame_id:03X}"
        self.frame_name = frame_name
        self.affected_signal = affected_signal
        self.category = category
        self.severity = severity
        self.diagnosis = diagnosis
        self.possible_causes = possible_causes
        self.raw_frame = raw_frame
        self.value = value
        self.expected = expected

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": round(self.timestamp, 6),
            "frame_id": self.hex_id,
            "frame_name": self.frame_name,
            "affected_signal": self.affected_signal,
            "category": self.category,
            "severity": self.severity,
            "diagnosis": self.diagnosis,
            "possible_causes": self.possible_causes,
            "value": str(self.value) if self.value is not None else "N/A",
            "expected": str(self.expected) if self.expected is not None else "N/A"
        }

    def __repr__(self):
        return (f"<Anomaly [{self.severity}] t={self.timestamp:.4f} {self.hex_id} ({self.frame_name}): "
                f"{self.category} in '{self.affected_signal}' - {self.diagnosis}>")


class CrossSignalRule:
    """Customizable cross-signal contradiction rule definition."""
    def __init__(self, name: str, description: str, severity: str,
                 eval_fn, diagnosis: str, possible_causes: List[str]):
        self.name = name
        self.description = description
        self.severity = severity
        self.eval_fn = eval_fn  # Function(state_dict) -> bool (True if anomaly triggered)
        self.diagnosis = diagnosis
        self.possible_causes = possible_causes


class AnomalyDetector:
    """Main Anomaly Detection Engine executing rule checks on decoded frame stream."""

    def __init__(self, dbc: DBCDatabase):
        self.dbc = dbc
        self.decoder = CANDecoder(dbc)

        # Tracking state across frames
        self.last_timestamps: Dict[int, float] = {}        # frame_id -> last_timestamp
        self.inter_intervals: Dict[int, List[float]] = {}  # frame_id -> list of delta_t
        self.nominal_periods: Dict[int, float] = {}        # frame_id -> nominal cycle time ms
        self.last_signal_values: Dict[str, float] = {}     # signal_name -> last physical value
        self.last_signal_timestamps: Dict[str, float] = {} # signal_name -> last timestamp
        self.last_counter_values: Dict[int, int] = {}      # frame_id -> sequence counter value

        # Vehicle global state buffer for cross-signal checks
        self.global_state: Dict[str, float] = {}
        self.global_state_timestamps: Dict[str, float] = {}

        # Default Cross-Signal Contradiction Rules
        self.cross_signal_rules: List[CrossSignalRule] = self._init_default_rules()

        # Learn nominal periods from DBC
        self._load_dbc_nominal_periods()

    def _load_dbc_nominal_periods(self):
        for fid, frame in self.dbc.frames.items():
            if frame.cycle_time_ms and frame.cycle_time_ms > 0:
                self.nominal_periods[fid] = frame.cycle_time_ms / 1000.0  # convert to seconds

    def _init_default_rules(self) -> List[CrossSignalRule]:
        rules = [
            CrossSignalRule(
                name="Vehicle Motion with Engine Off",
                description="Vehicle speed > 10 km/h while Engine RPM is 0",
                severity=Severity.CRITICAL,
                eval_fn=lambda s: s.get("Vehicle_Speed", 0) > 10.0 and s.get("Engine_Speed", 0) == 0.0,
                diagnosis="Physically impossible vehicle movement: Speed reported > 10 km/h with Engine OFF",
                possible_causes=[
                    "Engine ECU message spoofing attack",
                    "Wheel speed sensor failure / malicious injection",
                    "CAN bus replay attack of speed telemetry frame"
                ]
            ),
            CrossSignalRule(
                name="Transmission in PARK while Moving",
                description="Gear position is PARK while vehicle speed > 5 km/h",
                severity=Severity.CRITICAL,
                eval_fn=lambda s: s.get("Gear_Position", -1) == 0 and s.get("Vehicle_Speed", 0) > 5.0,
                diagnosis="Physical contradiction: Gear reported in PARK (0) while vehicle speed > 5 km/h",
                possible_causes=[
                    "Transmission Control Module (TCM) signal spoofing",
                    "Faulty gear selector position sensor",
                    "False status message injection by compromised ECU"
                ]
            ),
            CrossSignalRule(
                name="Contradictory Extreme Braking & Acceleration",
                description="Brake pedal > 50% while throttle pedal > 80%",
                severity=Severity.HIGH,
                eval_fn=lambda s: s.get("Brake_Pedal_Pct", 0) > 50.0 and s.get("Throttle_Pedal_Pct", 0) > 80.0,
                diagnosis="Driver control contradiction: Extreme hard brake (>50%) and max throttle (>80%) applied simultaneously",
                possible_causes=[
                    "Drive-by-wire system payload tampering",
                    "Pedal position sensor short-circuit",
                    "Malicious brake override / accelerator injection"
                ]
            ),
            CrossSignalRule(
                name="Door Open at High Vehicle Speed",
                description="Door state is OPEN while vehicle speed > 30 km/h",
                severity=Severity.HIGH,
                eval_fn=lambda s: s.get("Door_State", 0) == 1 and s.get("Vehicle_Speed", 0) > 30.0,
                diagnosis="Safety hazard: Vehicle door reported OPEN (1) while driving at > 30 km/h",
                possible_causes=[
                    "Body Control Module (BCM) door switch sensor glitch",
                    "Door latch sensor wire fault",
                    "Telemetry frame manipulation"
                ]
            ),
            CrossSignalRule(
                name="EV Charging plugged while Vehicle Driving",
                description="Charger plug connected while vehicle speed > 5 km/h",
                severity=Severity.CRITICAL,
                eval_fn=lambda s: s.get("Charger_Connected", 0) == 1 and s.get("Vehicle_Speed", 0) > 5.0,
                diagnosis="EV Safety Contradiction: High-voltage charger connected while vehicle is moving",
                possible_causes=[
                    "BMS / Charger control signal spoofing",
                    "Interlock switch circuit defect"
                ]
            )
        ]
        return rules

    def add_custom_rule(self, rule: CrossSignalRule):
        self.cross_signal_rules.append(rule)

    def analyze_log(self, raw_frames: List[CANFrame]) -> Tuple[List[DecodedFrame], List[Anomaly]]:
        """Processes a full list of raw frames and returns decoded frames & all detected anomalies."""
        decoded_frames: List[DecodedFrame] = []
        anomalies: List[Anomaly] = []

        if not raw_frames:
            return decoded_frames, anomalies

        # Sort frames chronologically by timestamp
        sorted_frames = sorted(raw_frames, key=lambda f: f.timestamp)

        # 1. First pass: baseline timing discovery for frames without explicit DBC cycle times
        self._learn_nominal_periods(sorted_frames)

        # 2. Main analysis loop
        for frame in sorted_frames:
            decoded = self.decoder.decode_frame(frame)
            decoded_frames.append(decoded)

            # Check 1: Out-of-Range Signals (Mandatory)
            out_of_range_anomalies = self._check_out_of_range(decoded)
            anomalies.extend(out_of_range_anomalies)

            # Check 2: Timing & Frequency Irregularities / DoS Flooding (Mandatory)
            timing_anomalies = self._check_timing_irregularities(frame, decoded)
            anomalies.extend(timing_anomalies)

            # Check 3: Data Corruption & DLC Mismatch (Optional)
            corruption_anomalies = self._check_data_corruption(frame, decoded)
            anomalies.extend(corruption_anomalies)

            # Update global vehicle state vector
            for sig_name, sig_dec in decoded.signals.items():
                self.global_state[sig_name] = sig_dec.physical_value
                self.global_state_timestamps[sig_name] = frame.timestamp

            # Check 4: Cross-Signal Logical Contradictions (Mandatory)
            contradiction_anomalies = self._check_logical_contradictions(frame, decoded)
            anomalies.extend(contradiction_anomalies)

        # Check 5: Missing Messages / ECU Timeout across the log timeline (Optional)
        timeout_anomalies = self._check_ecu_timeouts(sorted_frames)
        anomalies.extend(timeout_anomalies)

        # Sort anomalies by timestamp
        anomalies.sort(key=lambda a: a.timestamp)
        return decoded_frames, anomalies

    def _learn_nominal_periods(self, frames: List[CANFrame]):
        """Learns baseline inter-frame periods for frames without DBC cycle times."""
        timestamps_by_id: Dict[int, List[float]] = {}
        for f in frames:
            if f.frame_id not in timestamps_by_id:
                timestamps_by_id[f.frame_id] = []
            timestamps_by_id[f.frame_id].append(f.timestamp)

        for fid, ts_list in timestamps_by_id.items():
            if fid in self.nominal_periods:
                continue
            if len(ts_list) >= 5:
                deltas = [ts_list[i] - ts_list[i-1] for i in range(1, len(ts_list)) if ts_list[i] > ts_list[i-1]]
                if deltas:
                    # Use median delta as baseline nominal period
                    deltas.sort()
                    median_delta = deltas[len(deltas) // 2]
                    if median_delta > 0.001:  # ignore sub-millisecond noise
                        self.nominal_periods[fid] = median_delta

    def _check_out_of_range(self, decoded: DecodedFrame) -> List[Anomaly]:
        anomalies = []
        for sig_name, sig_dec in decoded.signals.items():
            if not sig_dec.is_valid_range:
                val = sig_dec.physical_value
                min_v = sig_dec.signal.min_val
                max_v = sig_dec.signal.max_val
                
                # Determine severity based on how far out of range
                deviation = 0.0
                if val < min_v and min_v != 0:
                    deviation = abs(val - min_v) / abs(min_v)
                elif val > max_v and max_v != 0:
                    deviation = abs(val - max_v) / abs(max_v)

                if sig_name in ["Vehicle_Speed", "Engine_Speed", "Steering_Angle", "Brake_Pressure"] and (val > max_v * 1.5 or val < min_v - 50):
                    severity = Severity.CRITICAL
                elif deviation > 0.3 or val > max_v * 1.2:
                    severity = Severity.HIGH
                else:
                    severity = Severity.MEDIUM

                anomalies.append(Anomaly(
                    timestamp=decoded.timestamp,
                    frame_id=decoded.frame_id,
                    frame_name=decoded.frame_name,
                    affected_signal=sig_name,
                    category=AnomalyCategory.OUT_OF_RANGE,
                    severity=severity,
                    diagnosis=f"Signal '{sig_name}' value ({val:.2f} {sig_dec.unit}) exceeds valid DBC bounds [{min_v}, {max_v}]",
                    possible_causes=[
                        "Sensor short-circuit or physical hardware fault",
                        "Out-of-range signal injection attack by malicious node",
                        "Corrupted CAN payload frame or scaling offset mismatch"
                    ],
                    raw_frame=decoded.raw_frame,
                    value=f"{val:.2f} {sig_dec.unit}",
                    expected=f"[{min_v}, {max_v}] {sig_dec.unit}"
                ))
        return anomalies

    def _check_timing_irregularities(self, frame: CANFrame, decoded: DecodedFrame) -> List[Anomaly]:
        anomalies = []
        fid = frame.frame_id
        t_curr = frame.timestamp

        if fid in self.last_timestamps:
            delta_t = t_curr - self.last_timestamps[fid]
            nom_period = self.nominal_periods.get(fid, None)

            if nom_period and nom_period > 0:
                ratio = delta_t / nom_period

                # 1. DoS / Message Flooding Detection: ratio < 0.20 (5x higher frequency than normal)
                if delta_t < 0.002 or ratio < 0.20:
                    anomalies.append(Anomaly(
                        timestamp=t_curr,
                        frame_id=fid,
                        frame_name=decoded.frame_name,
                        affected_signal="Bus Transmission Rate",
                        category=AnomalyCategory.DOS_FLOODING,
                        severity=Severity.CRITICAL if ratio < 0.1 else Severity.HIGH,
                        diagnosis=f"DoS Flooding Attack / High-Frequency Burst: Frame {decoded.hex_id} ({decoded.frame_name}) received with inter-message delta {delta_t*1000:.2f}ms (expected nominal {nom_period*1000:.1f}ms, ratio {ratio:.2f})",
                        possible_causes=[
                            "Compromised ECU flooding the CAN bus (Denial of Service attack)",
                            "Replay attack continuously resending captured telemetry frames",
                            "ECU bus controller malfunction sending rapid retries"
                        ],
                        raw_frame=frame,
                        value=f"Delta = {delta_t*1000:.2f} ms",
                        expected=f"Nominal = {nom_period*1000:.1f} ms"
                    ))

                # 2. Timing Jitter / Periodicity Violation: ratio > 2.0 (delayed frame)
                elif ratio > 2.0 and ratio < 3.5:
                    anomalies.append(Anomaly(
                        timestamp=t_curr,
                        frame_id=fid,
                        frame_name=decoded.frame_name,
                        affected_signal="Inter-Message Interval",
                        category=AnomalyCategory.TIMING_IRREGULARITY,
                        severity=Severity.MEDIUM,
                        diagnosis=f"Timing Jitter: Frame {decoded.hex_id} interval delayed ({delta_t*1000:.2f}ms vs nominal {nom_period*1000:.1f}ms)",
                        possible_causes=[
                            "High CAN bus load causing arbitration delays",
                            "ECU software task execution delay",
                            "Transient bus error frames"
                        ],
                        raw_frame=frame,
                        value=f"Delta = {delta_t*1000:.2f} ms",
                        expected=f"Nominal = {nom_period*1000:.1f} ms"
                    ))

        self.last_timestamps[fid] = t_curr
        return anomalies

    def _check_data_corruption(self, frame: CANFrame, decoded: DecodedFrame) -> List[Anomaly]:
        anomalies = []
        # 1. DLC Mismatch Check
        if decoded.dlc != decoded.expected_dlc:
            anomalies.append(Anomaly(
                timestamp=frame.timestamp,
                frame_id=frame.frame_id,
                frame_name=decoded.frame_name,
                affected_signal="Frame DLC",
                category=AnomalyCategory.DATA_CORRUPTION,
                severity=Severity.HIGH,
                diagnosis=f"DLC Mismatch: Frame {decoded.hex_id} payload length is {decoded.dlc} bytes, but DBC spec expects {decoded.expected_dlc} bytes",
                possible_causes=[
                    "Spoofed CAN frame injected by non-conforming ECU",
                    "Truncated message payload or protocol version mismatch",
                    "Corrupted log file line"
                ],
                raw_frame=frame,
                value=f"DLC = {decoded.dlc}",
                expected=f"DLC = {decoded.expected_dlc}"
            ))

        # 2. Counter / Sequence Check (if frame contains a counter signal like Alive_Counter or Msg_Counter)
        for sig_name, sig_dec in decoded.signals.items():
            if "counter" in sig_name.lower() or "alive" in sig_name.lower() or "seq" in sig_name.lower():
                curr_cnt = int(sig_dec.raw_value)
                if frame.frame_id in self.last_counter_values:
                    prev_cnt = self.last_counter_values[frame.frame_id]
                    max_cnt = (1 << sig_dec.signal.length)
                    expected_cnt = (prev_cnt + 1) % max_cnt

                    if curr_cnt != expected_cnt and curr_cnt != prev_cnt:
                        anomalies.append(Anomaly(
                            timestamp=frame.timestamp,
                            frame_id=frame.frame_id,
                            frame_name=decoded.frame_name,
                            affected_signal=sig_name,
                            category=AnomalyCategory.SEQUENCE_ERROR,
                            severity=Severity.HIGH,
                            diagnosis=f"Sequence Counter Error in '{sig_name}': Counter jumped from {prev_cnt} to {curr_cnt} (expected {expected_cnt})",
                            possible_causes=[
                                "Dropped / missing frames on CAN bus",
                                "Out-of-order frame injection by attacker node",
                                "ECU reset or counter initialization sync loss"
                            ],
                            raw_frame=frame,
                            value=f"Counter = {curr_cnt}",
                            expected=f"Counter = {expected_cnt}"
                        ))
                self.last_counter_values[frame.frame_id] = curr_cnt

        return anomalies

    def _check_logical_contradictions(self, frame: CANFrame, decoded: DecodedFrame) -> List[Anomaly]:
        anomalies = []
        for rule in self.cross_signal_rules:
            try:
                if rule.eval_fn(self.global_state):
                    # Check if anomaly was already flagged very recently (within 0.5s) to avoid duplicate spam
                    sig_key = f"{rule.name}_{decoded.frame_id}"
                    last_t = self.last_signal_timestamps.get(sig_key, 0)
                    if frame.timestamp - last_t > 0.5:
                        self.last_signal_timestamps[sig_key] = frame.timestamp
                        anomalies.append(Anomaly(
                            timestamp=frame.timestamp,
                            frame_id=frame.frame_id,
                            frame_name=decoded.frame_name,
                            affected_signal=rule.name,
                            category=AnomalyCategory.LOGICAL_CONTRADICTION,
                            severity=rule.severity,
                            diagnosis=f"Logical Contradiction Rule Violation: '{rule.name}' - {rule.diagnosis}",
                            possible_causes=rule.possible_causes,
                            raw_frame=frame,
                            value=f"State: {self._format_state_subset(rule)}",
                            expected="Valid Physical State Vector"
                        ))
            except Exception:
                pass
        return anomalies

    def _check_ecu_timeouts(self, sorted_frames: List[CANFrame]) -> List[Anomaly]:
        """Detects missing messages / ECU timeouts where periodic frames cease transmitting."""
        anomalies = []
        if not sorted_frames:
            return anomalies

        end_time = sorted_frames[-1].timestamp
        frame_last_seen: Dict[int, Tuple[float, CANFrame]] = {}

        for f in sorted_frames:
            frame_last_seen[f.frame_id] = (f.timestamp, f)

        for fid, nom_period in self.nominal_periods.items():
            if nom_period <= 0.005:  # skip extremely fast frames
                continue

            frame_def = self.dbc.get_frame(fid)
            frame_name = frame_def.name if frame_def else f"0x{fid:03X}"

            if fid in frame_last_seen:
                last_t, last_frame = frame_last_seen[fid]
                gap = end_time - last_t
                if gap > max(3.0 * nom_period, 2.0):  # frame missed for >3x period or >2 seconds before log end
                    anomalies.append(Anomaly(
                        timestamp=last_t + (nom_period * 2),
                        frame_id=fid,
                        frame_name=frame_name,
                        affected_signal="ECU Transmission Heartbeat",
                        category=AnomalyCategory.ECU_TIMEOUT,
                        severity=Severity.HIGH if nom_period < 0.1 else Severity.MEDIUM,
                        diagnosis=f"Missing Message / ECU Timeout: Frame {f'0x{fid:03X}'} ({frame_name}) stopped transmitting for {gap:.2f}s (expected period {nom_period*1000:.1f}ms)",
                        possible_causes=[
                            "Transmitting ECU went offline or suffered power loss",
                            "Targeted Bus Off attack forcing ECU error passive mode",
                            "Physical CAN high/low bus wire disconnect or gateway block"
                        ],
                        raw_frame=last_frame,
                        value=f"Silence duration = {gap:.2f} s",
                        expected=f"Nominal period = {nom_period*1000:.1f} ms"
                    ))
        return anomalies

    def _format_state_subset(self, rule: CrossSignalRule) -> str:
        items = []
        for k, v in self.global_state.items():
            if k in rule.description or k in rule.name or k in ["Vehicle_Speed", "Engine_Speed", "Gear_Position", "Brake_Pedal_Pct", "Throttle_Pedal_Pct", "Door_State"]:
                items.append(f"{k}={v}")
        return ", ".join(items[:4])
