"""
CAN Frame Payload Decoder Module
Extracts raw bit fields from CAN frame byte payloads (handling Intel/Little-Endian
and Motorola/Big-Endian byte ordering, signed two's complement, and bit shifts),
and applies scale/offset formulas to yield physical signal values.

100% offline, pure-Python implementation.
"""

from typing import Dict, Any, List, Optional, Tuple
from core.dbc_parser import DBCDatabase, Frame, Signal
from core.log_parser import CANFrame

class DecodedSignal:
    """Represents a decoded signal value with metadata."""
    def __init__(self, signal: Signal, raw_value: int, physical_value: float, is_valid_range: bool):
        self.signal = signal
        self.name = signal.name
        self.raw_value = raw_value
        self.physical_value = physical_value
        self.unit = signal.unit
        self.is_valid_range = is_valid_range
        self.enum_name = signal.get_enum_name(physical_value)

    def __repr__(self):
        val_str = f"{self.physical_value:.3f} {self.unit}".strip()
        if self.enum_name:
            val_str += f" ({self.enum_name})"
        status = "OK" if self.is_valid_range else "OUT-OF-RANGE"
        return f"<DecodedSignal {self.name}={val_str} [{status}]>"


class DecodedFrame:
    """Represents a decoded CAN frame containing its signals."""
    def __init__(self, frame: CANFrame, frame_def: Optional[Frame] = None):
        self.raw_frame = frame
        self.timestamp = frame.timestamp
        self.frame_id = frame.frame_id
        self.hex_id = frame.hex_id
        self.dlc = frame.dlc
        self.frame_name = frame_def.name if frame_def else f"Unknown_0x{frame.frame_id:03X}"
        self.transmitter = frame_def.transmitter if frame_def else "Unknown"
        self.expected_dlc = frame_def.dlc if frame_def else frame.dlc
        self.signals: Dict[str, DecodedSignal] = {}

    def add_decoded_signal(self, decoded_sig: DecodedSignal):
        self.signals[decoded_sig.name] = decoded_sig

    def get_signal_value(self, signal_name: str) -> Optional[float]:
        if signal_name in self.signals:
            return self.signals[signal_name].physical_value
        return None

    def __repr__(self):
        sig_count = len(self.signals)
        return f"<DecodedFrame t={self.timestamp:.4f} Name={self.frame_name} ID={self.hex_id} Signals={sig_count}>"


class CANDecoder:
    """Decodes raw CAN frames into physical signals using a DBC database."""

    def __init__(self, dbc: DBCDatabase):
        self.dbc = dbc

    def decode_frame(self, frame: CANFrame) -> DecodedFrame:
        """Decodes a single CAN frame payload using DBC definitions."""
        frame_def = self.dbc.get_frame(frame.frame_id)
        decoded = DecodedFrame(frame, frame_def)

        if not frame_def:
            return decoded

        # Convert data_bytes to integer bit array for bit manipulation
        payload_bytes = frame.data_bytes

        # First pass: check if frame uses multiplexing
        active_mux_val: Optional[int] = None
        mux_signal: Optional[Signal] = None

        for sig_name, sig in frame_def.signals.items():
            if sig.multiplexer == 'M':
                # Master multiplexer signal
                raw_val = self.extract_raw_signal(payload_bytes, sig)
                active_mux_val = int(raw_val)
                mux_signal = sig
                phys_val = sig.raw_to_physical(raw_val)
                in_range = sig.is_in_range(phys_val)
                decoded.add_decoded_signal(DecodedSignal(sig, raw_val, phys_val, in_range))
                break

        # Second pass: decode all matching signals
        for sig_name, sig in frame_def.signals.items():
            if sig.multiplexer == 'M':
                continue  # Already decoded master mux signal

            if sig.multiplexer and sig.multiplexer.startswith('m'):
                # Multiplexed signal, check if active
                try:
                    expected_mux = int(sig.multiplexer[1:])
                    if active_mux_val is not None and active_mux_val != expected_mux:
                        continue  # Inactive multiplexed signal
                except ValueError:
                    pass

            raw_val = self.extract_raw_signal(payload_bytes, sig)
            phys_val = sig.raw_to_physical(raw_val)
            in_range = sig.is_in_range(phys_val)
            decoded.add_decoded_signal(DecodedSignal(sig, raw_val, phys_val, in_range))

        return decoded

    @staticmethod
    def extract_raw_signal(payload: bytes, signal: Signal) -> int:
        """Extracts raw integer value from payload bytes given start_bit, length, endianness, sign."""
        if not payload:
            return 0

        # Create a 64-bit integer representation of up to 8 payload bytes
        # Byte 0 is lowest memory address.
        payload_len = len(payload)
        
        if signal.is_intel():
            # Intel (Little Endian) format:
            # start_bit is LSB. Bit positions increment across bytes:
            # Byte 0 bits 0..7, Byte 1 bits 8..15, Byte 2 bits 16..23 ...
            # Combine bytes into a single integer where Byte 0 is LSB byte
            val_64 = int.from_bytes(payload, byteorder='little')
            
            # Extract raw bits by right shifting start_bit and masking bit length
            mask = (1 << signal.length) - 1
            raw = (val_64 >> signal.start_bit) & mask

        else:
            # Motorola (Big Endian) format:
            # DBC specification for Motorola signals:
            # start_bit is MSB. Bits traverse backwards/across bytes.
            # To extract cleanly: convert bytes to big endian bit stream
            val_64 = int.from_bytes(payload, byteorder='big')
            total_bits = payload_len * 8
            
            # In Big Endian bit indexing from MSB (bit 0 = byte 0 bit 7):
            # DBC start_bit is defined as: byte_idx * 8 + (7 - bit_in_byte)
            # The signal spans from start_bit downwards to (start_bit - length + 1)
            # So shift amount from LSB of val_64 is: (total_bits - 1 - start_bit)
            
            # Standard DBC Motorola start bit formula:
            byte_idx = signal.start_bit // 8
            bit_in_byte = signal.start_bit % 8
            msb_pos = byte_idx * 8 + (7 - bit_in_byte)
            
            shift = (total_bits - 1) - (msb_pos + signal.length - 1)
            if shift < 0:
                shift = 0
            
            mask = (1 << signal.length) - 1
            raw = (val_64 >> shift) & mask

        # Handle signed two's complement
        if signal.is_signed:
            msb_mask = 1 << (signal.length - 1)
            if raw & msb_mask:
                raw -= (1 << signal.length)

        return raw
