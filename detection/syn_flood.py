from collections import defaultdict
import time

syn_tracker = defaultdict(list)

def detect_syn_flood(ip):
    current_time = time.time()

    syn_tracker[ip].append(current_time)

    syn_tracker[ip] = [
        t for t in syn_tracker[ip]
        if current_time - t < 10
    ]

    if len(syn_tracker[ip]) > 100:
        return True

    return False
