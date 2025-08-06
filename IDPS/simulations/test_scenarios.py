SCENARIOS = {
    "baseline": {
        "name": "Baseline Normal Traffic",
        "duration": 300,  # 5 minutes
        "attacks": [],
        "benign_traffic": [
            {"device": "thermostat", "type": "normal"},
            {"device": "security_cam", "type": "normal"},
            {"device": "smart_lock", "type": "normal"},
            {"device": "health_monitor", "type": "normal"}
        ]
    },
    "ddos_attack": {
        "name": "DDoS Attack Simulation",
        "duration": 180,  # 3 minutes
        "attacks": [
            {"device": "malicious_device", "type": "ddos"}
        ],
        "benign_traffic": [
            {"device": "thermostat", "type": "normal"}
        ]
    },
    "reconnaissance": {
        "name": "Network Reconnaissance",
        "duration": 120,
        "attacks": [
            {"device": "malicious_device", "type": "portscan"}
        ],
        "benign_traffic": [
            {"device": "security_cam", "type": "normal"}
        ]
    },
    "iot_exploit": {
        "name": "IoT Protocol Exploit",
        "duration": 150,
        "attacks": [
            {"device": "malicious_device", "type": "mqtt"}
        ],
        "benign_traffic": [
            {"device": "thermostat", "type": "normal"},
            {"device": "smart_lock", "type": "normal"}
        ]
    },
    "mixed_threats": {
        "name": "Mixed Threat Scenario",
        "duration": 240,
        "attacks": [
            {"device": "malicious_device", "type": "ddos"},
            {"device": "malicious_device", "type": "portscan"},
            {"device": "malicious_device", "type": "mqtt"}
        ],
        "benign_traffic": [
            {"device": "thermostat", "type": "normal"},
            {"device": "health_monitor", "type": "normal"}
        ]
    }
}