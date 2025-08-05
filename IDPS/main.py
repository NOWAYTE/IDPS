from edge.node import EdgeNode
from compliance.audit_logger import AuditLogger
import config
import signal
import sys

# Initialize systems
node = EdgeNode()
audit_logger = AuditLogger()

# Graceful shutdown handler
def shutdown_handler(sig, frame):
    print("\nShutting down IDPS...")
    audit_logger.finalize()
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

if __name__ == "__main__":
    print("Starting IoT IDPS Edge Node")
    print(f"Configuration: Batch Size={config.BATCH_SIZE}, "
          f"Threshold={config.ANOMALY_THRESHOLD}, "
          f"GDPR={config.GDPR_COMPLIANCE}")
    
    try:
        node.start()
    except KeyboardInterrupt:
        shutdown_handler(None, None)
    finally:
        audit_logger.finalize()