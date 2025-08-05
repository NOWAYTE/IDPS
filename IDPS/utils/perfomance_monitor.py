import numpy as np
import psutil
import time

class PerformanceMonitor:
    def __init__(self):
        self.latencies = {'signature': [], 'anomaly': []}
        self.memory_usage = []
        self.start_time = time.time()
    
    def record(self, detection_type, latency):
        if detection_type in ['signature', 'anomaly']:
            self.latencies[detection_type].append(latency)
        self.memory_usage.append(psutil.Process().memory_info().rss)
    
    def report(self):
        print("\n--- Performance Report ---")
        print(f"Uptime: {time.time() - self.start_time:.1f}s")
        
        # Latency stats
        for dtype in self.latencies:
            if self.latencies[dtype]:
                avg = np.mean(self.latencies[dtype])
                p95 = np.percentile(self.latencies[dtype], 95)
                print(f"{dtype.capitalize()} detection latency: "
                      f"avg={avg:.2f}ms, p95={p95:.2f}ms")
        
        # Memory stats
        if self.memory_usage:
            avg_mem = np.mean(self.memory_usage) / 1024 / 1024
            max_mem = max(self.memory_usage) / 1024 / 1024
            print(f"Memory usage: avg={avg_mem:.2f}MB, max={max_mem:.2f}MB")
        
        # Reset metrics
        self.latencies = {'signature': [], 'anomaly': []}
        self.memory_usage = []