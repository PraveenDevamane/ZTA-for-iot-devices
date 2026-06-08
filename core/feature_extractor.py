import math
from collections import defaultdict, deque
import time

class FlowFeatureExtractor:
    """
    Stateful extractor — keeps per-src-ip rolling windows.
    Designed for constrained devices: no numpy, pure stdlib.
    """
    def __init__(self, window_sec=30):
        self.window = window_sec
        # {src_ip: deque of (timestamp, port)}
        self._port_log = defaultdict(deque)
        # {src_ip: deque of (timestamp, pkt_count, byte_count)}
        self._pkt_log  = defaultdict(deque)

    def reset(self):
        """Clear rolling window state for a fresh run."""
        self._port_log.clear()
        self._pkt_log.clear()

    def _prune(self, dq, now):
        while dq and now - dq[0][0] > self.window:
            dq.popleft()

    def extract(self, flow: dict) -> dict:
        now = time.time()
        src = flow["src_ip"]

        # Port tracking (for port scan entropy)
        if flow["port"] and flow["port"] != "N/A":
            self._port_log[src].append((now, int(flow["port"])))
        self._prune(self._port_log[src], now)

        packets = int(flow.get("packets", 1) or 1)
        byte_count = int(flow.get("bytes", 0) or 0)

        # Packet/byte rate tracking
        self._pkt_log[src].append((now, packets, byte_count))
        self._prune(self._pkt_log[src], now)

        ports_seen = [p for _, p in self._port_log[src]]
        unique_ports = len(set(ports_seen))

        # Shannon entropy of port distribution (higher = more scan-like)
        port_entropy = 0.0
        if ports_seen:
            from collections import Counter
            counts = Counter(ports_seen)
            total = len(ports_seen)
            port_entropy = -sum(
                (c/total) * math.log2(c/total) for c in counts.values()
            )

        total_pkts = sum(p for _, p, _ in self._pkt_log[src])
        total_bytes = sum(b for _, _, b in self._pkt_log[src])
        if self._pkt_log[src]:
            elapsed = max(now - self._pkt_log[src][0][0], 1.0)
        else:
            elapsed = 1.0

        # Calculate packet size variance over the rolling window (for ML 'Variance' feature)
        sizes = [b for _, _, b in self._pkt_log[src]]
        if len(sizes) > 1:
            mean = sum(sizes) / len(sizes)
            variance = sum((x - mean) ** 2 for x in sizes) / len(sizes)
        else:
            variance = 0.0

        return {
            "src_ip":            src,
            "dst_ip":            flow["dst_ip"],
            "proto":             flow["proto"],
            "pkt_rate":          round(total_pkts / elapsed, 2),
            "byte_rate":         round(total_bytes / elapsed, 2),
            "unique_ports":      unique_ports,
            "port_entropy":      round(port_entropy, 4),
            "pkt_size_variance": round(variance, 4),
            "window_pkts":       total_pkts,
            "is_response":       flow.get("is_response", False),
        }

