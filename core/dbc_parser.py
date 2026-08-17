"""
Native DBC Parser for CAN Database Files (.dbc)
Parses frame definitions (BO_), signal definitions (SG_), byte order (Motorola/Intel),
signedness, scale, offset, min/max bounds, units, value descriptors (VAL_), and message attributes.
100% offline, pure-Python with zero external dependencies.
"""

import re
from typing import Dict, List, Optional, Union, Tuple, Any

class Signal:
    """Represents a single CAN signal within a frame definition."""
    def __init__(self, name: str, start_bit: int, length: int, byte_order: int,
                 is_signed: bool, scale: float, offset: float, min_val: float,
                 max_val: float, unit: str, receivers: List[str],
                 multiplexer: Optional[str] = None, val_table: Optional[Dict[int, str]] = None):
        self.name = name
        self.start_bit = start_bit
        self.length = length
        self.byte_order = byte_order  # 1 = Intel (Little Endian), 0 = Motorola (Big Endian)
        self.is_signed = is_signed
        self.scale = scale
        self.offset = offset
        self.min_val = min_val
        self.max_val = max_val
        self.unit = unit
        self.receivers = receivers
        self.multiplexer = multiplexer  # 'M' for multiplexor, 'm<N>' for multiplexed signal
        self.val_table = val_table or {}

    def is_intel(self) -> bool:
        return self.byte_order == 1

    def is_motorola(self) -> bool:
        return self.byte_order == 0

    def raw_to_physical(self, raw_val: Union[int, float]) -> float:
        """Converts raw integer value to scaled physical float value."""
        return (raw_val * self.scale) + self.offset

    def physical_to_raw(self, phys_val: float) -> int:
        """Converts physical float value back to raw integer."""
        if self.scale == 0:
            return 0
        return int(round((phys_val - self.offset) / self.scale))

    def is_in_range(self, phys_val: float) -> bool:
        """Checks if a physical value lies within valid min/max bounds."""
        tol = 1e-6
        return (self.min_val - tol) <= phys_val <= (self.max_val + tol)

    def get_enum_name(self, raw_or_phys: Union[int, float]) -> Optional[str]:
        """Returns string representation for enumerated value if present."""
        val_int = int(raw_or_phys)
        return self.val_table.get(val_int, None)

    def __repr__(self):
        return (f"<Signal {self.name}: start={self.start_bit}, len={self.length}, "
                f"order={'Intel' if self.byte_order==1 else 'Motorola'}, scale={self.scale}, "
                f"offset={self.offset}, range=[{self.min_val}, {self.max_val}] '{self.unit}'>")


class Frame:
    """Represents a CAN message frame definition (BO_)."""
    def __init__(self, frame_id: int, name: str, dlc: int, transmitter: str):
        self.frame_id = frame_id  # Integer CAN ID (standard or extended)
        self.name = name
        self.dlc = dlc  # Expected payload length in bytes (0-8 or 0-64 for CAN FD)
        self.transmitter = transmitter
        self.signals: Dict[str, Signal] = {}
        self.cycle_time_ms: Optional[float] = None  # Expected period in milliseconds

    @property
    def hex_id(self) -> str:
        return f"0x{self.frame_id:03X}"

    def add_signal(self, signal: Signal):
        self.signals[signal.name] = signal

    def get_signal(self, signal_name: str) -> Optional[Signal]:
        return self.signals.get(signal_name)

    def __repr__(self):
        return f"<Frame {self.name} (ID: {self.hex_id}, DLC: {self.dlc}, Node: {self.transmitter}, Cycle: {self.cycle_time_ms}ms, Signals: {len(self.signals)})>"


class DBCDatabase:
    """Main Database class representing a parsed .dbc file."""
    def __init__(self, filepath: Optional[str] = None):
        self.version: str = ""
        self.nodes: List[str] = []
        self.frames: Dict[int, Frame] = {}      # Frame ID -> Frame
        self.frame_by_name: Dict[str, Frame] = {} # Frame Name -> Frame
        self.val_tables: Dict[str, Dict[int, str]] = {}

        if filepath:
            self.parse_file(filepath)

    def parse_file(self, filepath: str):
        """Parses a DBC file from filesystem path."""
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        self.parse_string(content)

    def parse_string(self, content: str):
        """Parses DBC content string."""
        lines = content.splitlines()
        current_frame: Optional[Frame] = None

        bo_pattern = re.compile(r'^\s*BO_\s+(\d+)\s+(\w+)\s*:\s*(\d+)\s+(\w+)')
        sg_pattern = re.compile(
            r'^\s*SG_\s+(\w+)\s*(m\d+|M)?\s*:\s*(\d+)\|(\d+)@([01])([+-])\s*\(\s*([\d.eE+-]+)\s*,\s*([\d.eE+-]+)\s*\)\s*\[\s*([\d.eE+-]+)\s*\|\s*([\d.eE+-]+)\s*\]\s*"([^"]*)"\s*(.*)'
        )
        val_pattern = re.compile(r'^\s*VAL_\s+(\d+)\s+(\w+)\s+(.*);')
        ba_cycle_pattern = re.compile(r'^\s*BA_\s+"GenMsgCycleTime"\s+BO_\s+(\d+)\s+(\d+);')

        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith('//'):
                continue

            if line_str.startswith('VERSION'):
                ver_match = re.search(r'VERSION\s+"([^"]*)"', line_str)
                if ver_match:
                    self.version = ver_match.group(1)
                continue

            if line_str.startswith('BU_:'):
                nodes_str = line_str[4:].strip()
                self.nodes = nodes_str.split()
                continue

            bo_match = bo_pattern.match(line_str)
            if bo_match:
                frame_id = int(bo_match.group(1))
                frame_name = bo_match.group(2)
                dlc = int(bo_match.group(3))
                transmitter = bo_match.group(4)

                current_frame = Frame(frame_id, frame_name, dlc, transmitter)
                self.frames[frame_id] = current_frame
                self.frame_by_name[frame_name] = current_frame
                continue

            sg_match = sg_pattern.match(line_str)
            if sg_match and current_frame:
                sig_name = sg_match.group(1)
                mux = sg_match.group(2)  # 'M' or 'm1' etc
                start_bit = int(sg_match.group(3))
                bit_len = int(sg_match.group(4))
                byte_order = int(sg_match.group(5))  # 1=Intel, 0=Motorola
                sign_char = sg_match.group(6)        # + or -
                scale = float(sg_match.group(7))
                offset = float(sg_match.group(8))
                min_val = float(sg_match.group(9))
                max_val = float(sg_match.group(10))
                unit = sg_match.group(11)
                receivers_raw = sg_match.group(12).strip()
                receivers = [r.strip() for r in receivers_raw.split(',') if r.strip()]

                signal = Signal(
                    name=sig_name,
                    start_bit=start_bit,
                    length=bit_len,
                    byte_order=byte_order,
                    is_signed=(sign_char == '-'),
                    scale=scale,
                    offset=offset,
                    min_val=min_val,
                    max_val=max_val,
                    unit=unit,
                    receivers=receivers,
                    multiplexer=mux
                )
                current_frame.add_signal(signal)
                continue

            ba_match = ba_cycle_pattern.match(line_str)
            if ba_match:
                frame_id = int(ba_match.group(1))
                cycle_ms = float(ba_match.group(2))
                if frame_id in self.frames:
                    self.frames[frame_id].cycle_time_ms = cycle_ms
                continue

            val_match = val_pattern.match(line_str)
            if val_match:
                frame_id = int(val_match.group(1))
                sig_name = val_match.group(2)
                raw_pairs = val_match.group(3)
                pair_matches = re.findall(r'(\d+)\s+"([^"]*)"', raw_pairs)
                val_dict = {int(v): s for v, s in pair_matches}

                if frame_id in self.frames:
                    sig = self.frames[frame_id].get_signal(sig_name)
                    if sig:
                        sig.val_table = val_dict
                continue

    def get_frame(self, frame_id: int) -> Optional[Frame]:
        return self.frames.get(frame_id)

    def get_frame_by_name(self, name: str) -> Optional[Frame]:
        return self.frame_by_name.get(name)

    def __repr__(self):
        return f"<DBCDatabase version='{self.version}', frames={len(self.frames)}, nodes={len(self.nodes)}>"
