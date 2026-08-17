"""
Sample Log Files Generator Script
Generates realistic automotive CAN log datasets (.log, .asc, .trc, .csv) for testing:
1. 01_normal_driving.log (Clean baseline)
2. 02_out_of_range.log (Mandatory Anomaly 1)
3. 03_dos_flooding.log (Mandatory Anomaly 2)
4. 04_contradiction.log (Mandatory Anomaly 3)
5. 05_ecu_timeout.log (Optional Anomaly 1)
6. 06_data_corruption.log (Optional Anomaly 2)
7. 07_master_cyberattack_demo.log (Combined Evaluation Scenario)
"""

import os
import struct

def encode_engine_data(rpm, throttle_pct, temp_c, counter):
    raw_rpm = int(round(rpm / 0.25)) & 0xFFFF
    raw_throttle = int(round(throttle_pct / 0.4)) & 0xFF
    raw_temp = int(round(temp_c + 40)) & 0xFF
    raw_cnt = counter & 0x0F
    
    b0 = raw_rpm & 0xFF
    b1 = (raw_rpm >> 8) & 0xFF
    b2 = raw_throttle
    b3 = raw_temp
    b4 = raw_cnt
    return bytes([b0, b1, b2, b3, b4, 0x00, 0x00, 0x00])

def encode_transmission_data(gear, clutch):
    b0 = (gear & 0x0F) | ((clutch & 0x0F) << 4)
    return bytes([b0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

def encode_abs_data(speed_kmh, brake_pct, pressure_bar):
    raw_speed = int(round(speed_kmh / 0.01)) & 0xFFFF
    raw_brake = int(round(brake_pct / 0.4)) & 0xFF
    raw_press = int(round(pressure_bar / 0.1)) & 0xFFFF
    
    b0 = raw_speed & 0xFF
    b1 = (raw_speed >> 8) & 0xFF
    b2 = raw_brake
    b3 = raw_press & 0xFF
    b4 = (raw_press >> 8) & 0xFF
    return bytes([b0, b1, b2, b3, b4, 0x00, 0x00, 0x00])

def encode_bcm_data(door_state, headlight_state):
    b0 = (door_state & 0x03) | ((headlight_state & 0x03) << 2)
    return bytes([b0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

def generate_logs():
    out_dir = os.path.dirname(os.path.abspath(__file__))

    # 1. Clean Normal Driving Log
    lines_01 = ["date Mon Aug 17 10:00:00 2026", "base hex timestamps absolute"]
    t = 0.0
    cnt = 0
    for i in range(200):
        t += 0.01
        cnt = (cnt + 1) % 16
        speed = min(i * 0.4, 60.0)
        rpm = 800 + (speed * 25)
        gear = 3 if speed > 10 else 1  # DRIVE or REVERSE
        
        # Engine Frame (0x100 = 256)
        p_eng = encode_engine_data(rpm, 20.0, 90.0, cnt).hex(' ').upper()
        lines_01.append(f"   {t:09.6f} 1  100             Rx   d 8 {p_eng}")
        
        # ABS Frame (0x102 = 258)
        p_abs = encode_abs_data(speed, 0.0, 0.0).hex(' ').upper()
        lines_01.append(f"   {t:09.6f} 1  102             Rx   d 8 {p_abs}")
        
        # Transmission Frame (0x101 = 257) every 20ms
        if i % 2 == 0:
            p_trx = encode_transmission_data(gear, 0).hex(' ').upper()
            lines_01.append(f"   {t:09.6f} 1  101             Rx   d 8 {p_trx}")
            
        # BCM Frame (0x200 = 512) every 100ms
        if i % 10 == 0:
            p_bcm = encode_bcm_data(0, 1).hex(' ').upper()
            lines_01.append(f"   {t:09.6f} 1  200             Rx   d 8 {p_bcm}")

    with open(os.path.join(out_dir, "01_normal_driving.log"), "w") as f:
        f.write("\n".join(lines_01))

    # 2. Out-of-Range Sensor Fault Log
    lines_02 = list(lines_01[:50])
    # Add corrupted out-of-range sensor frames
    t = 0.51
    # Engine temp spike to 210 °C
    p_err1 = encode_engine_data(2500, 30.0, 210.0, 5).hex(' ').upper()
    lines_02.append(f"   {t:09.6f} 1  100             Rx   d 8 {p_err1}")
    t += 0.01
    # Speed overflow to 320 km/h
    p_err2 = encode_abs_data(320.0, 0.0, 0.0).hex(' ').upper()
    lines_02.append(f"   {t:09.6f} 1  102             Rx   d 8 {p_err2}")
    
    with open(os.path.join(out_dir, "02_out_of_range.log"), "w") as f:
        f.write("\n".join(lines_02))

    # 3. DoS Flooding Attack Log
    lines_03 = list(lines_01[:30])
    t = 0.31
    # Rapid flooding burst of ABS frames at 0.1ms interval
    for _ in range(40):
        t += 0.0001
        p_flood = encode_abs_data(50.0, 100.0, 180.0).hex(' ').upper()
        lines_03.append(f"   {t:09.6f} 1  102             Rx   d 8 {p_flood}")

    with open(os.path.join(out_dir, "03_dos_flooding.log"), "w") as f:
        f.write("\n".join(lines_03))

    # 4. Logical Contradiction Log
    lines_04 = list(lines_01[:30])
    t = 0.31
    # Speed > 50 km/h but Engine RPM = 0
    p_eng_off = encode_engine_data(0, 0.0, 90.0, 1).hex(' ').upper()
    p_abs_fast = encode_abs_data(75.0, 0.0, 0.0).hex(' ').upper()
    p_gear_park = encode_transmission_data(0, 0).hex(' ').upper()  # Gear PARK (0)
    lines_04.append(f"   {t:09.6f} 1  100             Rx   d 8 {p_eng_off}")
    lines_04.append(f"   {t+0.002:09.6f} 1  102             Rx   d 8 {p_abs_fast}")
    lines_04.append(f"   {t+0.004:09.6f} 1  101             Rx   d 8 {p_gear_park}")

    with open(os.path.join(out_dir, "04_contradiction.log"), "w") as f:
        f.write("\n".join(lines_04))

    # 5. ECU Timeout Log
    lines_05 = list(lines_01[:40])
    # ABS ECU (0x102) stops transmitting after t=0.4s while trace continues for another 4 seconds
    t = 0.41
    for i in range(100):
        t += 0.04
        p_eng = encode_engine_data(1500, 10.0, 90.0, i%16).hex(' ').upper()
        lines_05.append(f"   {t:09.6f} 1  100             Rx   d 8 {p_eng}")
        
    with open(os.path.join(out_dir, "05_ecu_timeout.log"), "w") as f:
        f.write("\n".join(lines_05))

    # 6. Master Cyberattack Evaluation Scenario Log (CSV & LOG format)
    lines_07 = list(lines_01[:40])
    t = 0.41
    # Phase A: DoS Flooding
    for _ in range(30):
        t += 0.0002
        p_flood = encode_abs_data(45.0, 0.0, 0.0).hex(' ').upper()
        lines_07.append(f"   {t:09.6f} 1  102             Rx   d 8 {p_flood}")
    
    # Phase B: Out of Range & DLC Mismatch
    t += 0.05
    p_corrupt_dlc = "FF FF FF FF"  # 4 bytes instead of 8
    lines_07.append(f"   {t:09.6f} 1  100             Rx   d 4 {p_corrupt_dlc}")
    
    # Phase C: Logical Contradictions
    t += 0.05
    lines_07.append(f"   {t:09.6f} 1  100             Rx   d 8 {encode_engine_data(0, 0.0, 90.0, 2).hex(' ').upper()}")
    lines_07.append(f"   {t+0.002:09.6f} 1  102             Rx   d 8 {encode_abs_data(85.0, 0.0, 0.0).hex(' ').upper()}")
    lines_07.append(f"   {t+0.004:09.6f} 1  101             Rx   d 8 {encode_transmission_data(0, 0).hex(' ').upper()}")

    with open(os.path.join(out_dir, "07_master_cyberattack_demo.log"), "w") as f:
        f.write("\n".join(lines_07))

    # Also create a CSV version for CSV parser validation
    csv_lines = ["Timestamp,Frame_ID,DLC,Data"]
    for line in lines_07:
        if line.startswith("date") or line.startswith("base"):
            continue
        parts = line.strip().split()
        if len(parts) >= 6:
            ts = parts[0]
            fid = f"0x{int(parts[2], 16):03X}"
            dlc = parts[5]
            payload = "".join(parts[6:])
            csv_lines.append(f"{ts},{fid},{dlc},{payload}")

    with open(os.path.join(out_dir, "07_master_cyberattack_demo.csv"), "w") as f:
        f.write("\n".join(csv_lines))

if __name__ == "__main__":
    generate_logs()
    print("Sample CAN log datasets successfully generated.")
