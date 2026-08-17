import cantools
from pathlib import Path

class DBCDecoder:
    def __init__(self, dbc_path: Path):
        self.db = cantools.database.load_file(str(dbc_path))
        # build id -> message map
        self.msg_by_id = {m.frame_id: m for m in self.db.messages}

    def decode(self, can_id, data_bytes):
        """
        Returns dict: {signal_name: value, ...}
        If unknown message returns None.
        """
        m = self.msg_by_id.get(can_id)
        if m is None:
            return None
        try:
            # Message objects in cantools provide a decode method
            return m.decode(data_bytes)
        except Exception:
            # fallback
            try:
                return self.db.decode_message(can_id, data_bytes)
            except Exception:
                return None
