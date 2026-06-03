from collections import defaultdict
import time

scan_tracker = defaultdict(list)

def detect_port_scan(ip, port):
    current_time = time.time()

    scan_tracker[ip].append((port, current_time))

    scan_tracker[ip] = [
        (p, t)
        for p, t in scan_tracker[ip]
        if current_time - t < 60
    ]

    ports = set(p for p, _ in scan_tracker[ip])

    if len(ports) > 20:
        return True

    return False
