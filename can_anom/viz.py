import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os


def plot_signal_history(detector, message_id, signal_name, out_path):
    """
    Simple plot helper: extract times and values for a signal and save a PNG.
    """
    vals = []
    times = []
    for ts, decoded in detector.signal_history.get(message_id, []):
        if decoded and signal_name in decoded:
            times.append(ts)
            vals.append(decoded[signal_name])
    if not times:
        return None
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    plt.figure(figsize=(8,3))
    plt.plot(times, vals, '-o', markersize=2)
    plt.title(f"{message_id}:{signal_name}")
    plt.xlabel('time (s)')
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
    return out_path
