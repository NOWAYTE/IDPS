import json
import os
from pathlib import Path
from datetime import datetime

class IDPSLogger:
    def __init__(self):
        self.results_dir = Path('results')
        self.results_dir.mkdir(exist_ok=True)
        self.metrics_file = self.results_dir / 'metrics.csv'
        self.detections_file = self.results_dir / 'detections.json'
        self._init_metrics_file()
    
    def _init_metrics_file(self):
        if not self.metrics_file.exists():
            with open(self.metrics_file, 'w') as f:
                f.write('timestamp,metric,value,source,target,details\n')
    
    def log_metric(self, metric, value, source=None, target=None, details=None):
        """Log a system or network metric"""
        timestamp = datetime.utcnow().isoformat()
        with open(self.metrics_file, 'a') as f:
            f.write(f'{timestamp},{metric},{value},"{source}","{target}","{details or ""}"\n')
    
    def log_detection(self, detection_type, confidence, source_ip, target_ip, details=None):
        """Log a security detection event"""
        detection = {
            'timestamp': datetime.utcnow().isoformat(),
            'type': detection_type,
            'confidence': float(confidence),
            'source_ip': source_ip,
            'target_ip': target_ip,
            'details': details or {}
        }
        with open(self.detections_file, 'a') as f:
            f.write(json.dumps(detection) + '\n')
        return detection

# Global logger instance
logger = IDPSLogger()
