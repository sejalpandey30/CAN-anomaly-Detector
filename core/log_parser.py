"""
Multi-Format CAN Log File Parser
Parses pre-recorded CAN log files in:
- Vector ASC format (.log / .asc)
- PEAK PCAN Trace format (.trc)
- SocketCAN candump format (.log)
- Comma-Separated Values format (.csv)

Normalizes raw frames into standardized CANFrame instances.
100% offline, pure-Python implementation.
"""

import re
import csv
from typing import List, Optional, Tuple, Dict, Any

class CANFrame:
    """Represents a raw CAN frame captured on the bus."""
    def __init__(self, timestamp: float, frame_id: int, dlc: int, data_bytes: bytes, channel: str = "can0"):
        self.timestamp = timestamp
        self.frame_id = frame_id  # Integer CAN ID
        self.dlc = dlc
        self.data_bytes = data_bytes
        self.channel = channel

    @property
    def hex_id(self) -> str:
        return f"0x{self.frame_id:03X}"

    @property
    def hex_data(self) -> str:
        return self.data_bytes.hex().upper()

    def __repr__(self):
        return f"<CANFrame t={self.timestamp:.6f} ID={self.hex_id} DLC={self.dlc} Data={self.hex_data}>"


class CANLogParser:
    """Unified multi-format CAN log reader."""

    @staticmethod
    def parse_file(filepath: str) -> List[CANFrame]:
        """Auto-detects format from file extension/content and returns frame list."""
        ext = filepath.lower().split('.')[-1]
        
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read(4096)
            f.seek(0)

            if ext == 'csv' or ',' in content.splitlines()[0] if content else False:
                return CANLogParser.parse_csv(filepath)
            elif ext == 'trc' or 'PEAK' in content or ';---' in content:
                return CANLogParser.parse_peak_trc(filepath)
            elif '(' in content and ') can' in content:
                return CANLogParser.parse_socketcan(filepath)
            else:
                # Default to Vector ASC / General log parser
                return CANLogParser.parse_vector_asc(filepath)

    @staticmethod
    def parse_vector_asc(filepath: str) -> List[CANFrame]:
        """Parses Vector ASC (.log / .asc) format."""
        frames: List[CANFrame] = []
        # Pattern: timestamp channel frame_id Rx/Tx d dlc byte0 byte1 ...
        # e.g., "   0.012345 1  100             Rx   d 8 01 02 03 04 05 06 07 08"
        # or "date Mon Jan 01..." lines
        pattern = re.compile(
            r'^\s*([\d.]+)\s+(\w+)\s+([0-9a-fA-F]+)x?\s+(Rx|Tx)\s+d\s+(\d+)\s+((?:[0-9a-fA-F]{2}\s*)+)'
        )

        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line_str = line.strip()
                if not line_str or line_str.startswith('date') or line_str.startswith('base') or line_str.startswith('//'):
                    continue
                match = pattern.match(line_str)
                if match:
                    t = float(match.group(1))
                    channel = match.group(2)
                    frame_id_hex = match.group(3)
                    frame_id = int(frame_id_hex, 16)
                    dlc = int(match.group(5))
                    data_hex_str = match.group(6).replace(' ', '')
                    data_bytes = bytes.fromhex(data_hex_str[:dlc*2])
                    frames.append(CANFrame(t, frame_id, dlc, data_bytes, channel))
                else:
                    # Alternative simple space-separated format: timestamp frame_id dlc hex_payload
                    parts = line_str.split()
                    if len(parts) >= 4:
                        try:
                            t = float(parts[0])
                            fid = int(parts[1], 16) if '0x' in parts[1] or re.match(r'^[0-9a-fA-F]+$', parts[1]) else int(parts[1])
                            dlc = int(parts[2])
                            data_hex = parts[3].replace(' ', '')
                            data_bytes = bytes.fromhex(data_hex[:dlc*2])
                            frames.append(CANFrame(t, fid, dlc, data_bytes))
                        except (ValueError, IndexError):
                            continue
        return frames

    @staticmethod
    def parse_peak_trc(filepath: str) -> List[CANFrame]:
        """Parses PEAK PCAN Trace (.trc) format."""
        frames: List[CANFrame] = []
        # Line format: 1)  123.456  DT  0064  Rx  8  01 02 03 04 05 06 07 08
        pattern = re.compile(
            r'^\s*\d+\)\s+([\d.]+)\s+DT\s+([0-9a-fA-F]+)\s+(Rx|Tx)\s+(\d+)\s+((?:[0-9a-fA-F]{2}\s*)+)'
        )

        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line_str = line.strip()
                if line_str.startswith(';') or not line_str:
                    continue
                match = pattern.match(line_str)
                if match:
                    t = float(match.group(1)) / 1000.0 if float(match.group(1)) > 10000 else float(match.group(1))
                    frame_id = int(match.group(2), 16)
                    dlc = int(match.group(4))
                    data_hex = match.group(5).replace(' ', '')
                    data_bytes = bytes.fromhex(data_hex[:dlc*2])
                    frames.append(CANFrame(t, frame_id, dlc, data_bytes))
        return frames

    @staticmethod
    def parse_socketcan(filepath: str) -> List[CANFrame]:
        """Parses SocketCAN candump format, e.g., '(1620000000.123456) can0 123#0102030405060708'."""
        frames: List[CANFrame] = []
        pattern = re.compile(
            r'^\s*\(([\d.]+)\)\s+(\w+)\s+([0-9a-fA-F]+)#([0-9a-fA-F]*)'
        )

        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line_str = line.strip()
                match = pattern.match(line_str)
                if match:
                    t = float(match.group(1))
                    channel = match.group(2)
                    frame_id = int(match.group(3), 16)
                    data_hex = match.group(4)
                    data_bytes = bytes.fromhex(data_hex)
                    dlc = len(data_bytes)
                    frames.append(CANFrame(t, frame_id, dlc, data_bytes, channel))
        return frames

    @staticmethod
    def parse_csv(filepath: str) -> List[CANFrame]:
        """Parses CSV format containing timestamp, frame_id, dlc, data."""
        frames: List[CANFrame] = []

        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            header = None

            for row in reader:
                if not row or not any(row):
                    continue
                # Detect header
                if header is None:
                    row_lower = [c.lower().strip() for c in row]
                    if 'time' in row_lower[0] or 'timestamp' in row_lower[0] or 'id' in row_lower[1]:
                        header = row_lower
                        continue
                    else:
                        header = ['timestamp', 'frame_id', 'dlc', 'data']

                try:
                    t = float(row[0].strip())
                    fid_str = row[1].strip()
                    fid = int(fid_str, 16) if ('0x' in fid_str or any(c in fid_str.lower() for c in 'abcdef')) else int(fid_str)
                    
                    if len(row) >= 4:
                        dlc = int(row[2].strip())
                        data_str = row[3].strip().replace(' ', '').replace('0x', '')
                        data_bytes = bytes.fromhex(data_str[:dlc*2])
                    elif len(row) == 3:
                        data_str = row[2].strip().replace(' ', '').replace('0x', '')
                        data_bytes = bytes.fromhex(data_str)
                        dlc = len(data_bytes)
                    else:
                        continue

                    frames.append(CANFrame(t, fid, dlc, data_bytes))
                except (ValueError, IndexError):
                    continue
        return frames
