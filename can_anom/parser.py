import csv
from pathlib import Path
import re
from typing import Iterator


def _hexbytes_to_bytes(s: str):
    if s is None:
        return b""
    s = str(s)
    s = re.sub(r'[^0-9A-Fa-f]', '', s)
    if s == "":
        return b""
    return bytes.fromhex(s)


class LogParser:
    """
    Very permissive CSV parser:
    Expects CSV with at least: timestamp, id, data
    timestamp: seconds (float) or microseconds integer
    id: decimal or hex (e.g., 0x123)
    data: hex bytes like '0x112233' or '11 22 33'
    """
    def __init__(self, path: Path):
        self.path = Path(path)
        self.file = open(self.path, newline='')

    def __iter__(self) -> Iterator:
        # Try CSV first
        reader = csv.DictReader(self.file)
        if reader.fieldnames is None:
            self.file.seek(0)
            for line in self.file:
                parts = line.strip().split()
                if len(parts) < 3:
                    continue
                try:
                    ts = float(parts[0])
                    can_id = int(parts[1], 0)
                    data = _hexbytes_to_bytes(parts[2])
                    yield ts, can_id, data
                except Exception:
                    continue
            return

        # Lowercase header keys
        keys = [k.lower() for k in reader.fieldnames or []]
        # heuristics
        ts_key = next((k for k in keys if 'time' in k or 'timestamp' in k), None)
        id_key = next((k for k in keys if k in ('id','can_id','frame_id') or 'id'==k), None)
        data_key = next((k for k in keys if 'data' in k or 'payload' in k or 'raw' in k), None)

        if not (ts_key and id_key and data_key):
            # Fall back: try to parse space-separated simple logs
            self.file.seek(0)
            for line in self.file:
                parts = line.strip().split()
                if len(parts) < 3:
                    continue
                try:
                    ts = float(parts[0])
                    can_id = int(parts[1], 0)
                    data = _hexbytes_to_bytes(parts[2])
                    yield ts, can_id, data
                except Exception:
                    continue
            return

        # map original header names to lowercase keys
        mapping = dict(zip(keys, reader.fieldnames))
        for row in reader:
            try:
                ts = float(row[mapping[ts_key]])
                can_id_str = row[mapping[id_key]]
                can_id = int(can_id_str, 0)
                raw = row[mapping[data_key]]
                data = _hexbytes_to_bytes(raw)
                yield ts, can_id, data
            except Exception:
                continue
