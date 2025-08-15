SCENARIOS = {
    "baseline": {
        "name": "Baseline Normal Traffic",
        "duration": 300,  # 5 minutes
        "attacks": [],
        "benign_traffic": [
            {"device": "therm", "type": "normal"},
            {"device": "cam", "type": "normal"},
            {"device": "lock", "type": "normal"},
            {"device": "health", "type": "normal"}
        ]
    },
    "ddos_attack": {
        "name": "DDoS Attack Simulation",
        "duration": 180,  # 3 minutes
        "attacks": [
            {"device": "malicious", "type": "ddos"}
        ],
        "benign_traffic": [
            {"device": "therm", "type": "normal"}
        ]
    },
    "reconnaissance": {
        "name": "Network Reconnaissance",
        "duration": 120,
        "attacks": [
            {"device": "malicious", "type": "portscan"}
        ],
        "benign_traffic": [
            {"device": "cam", "type": "normal"}
        ]
    },
    "iot_exploit": {
        "name": "IoT Protocol Exploit",
        "duration": 150,
        "attacks": [
            {"device": "malicious", "type": "mqtt"}
        ],
        "benign_traffic": [
            {"device": "therm", "type": "normal"},
            {"device": "lock", "type": "normal"}
        ]
    },
    "mixed_threats": {
        "name": "Mixed Threat Scenario",
        "duration": 240,
        "attacks": [
            {"device": "malicious", "type": "ddos"},
            {"device": "malicious", "type": "portscan"},
            {"device": "malicious", "type": "mqtt"}
        ],
        "benign_traffic": [
            {"device": "therm", "type": "normal"},
            {"device": "cam", "type": "normal"},
            {"device": "lock", "type": "normal"},
            {"device": "health", "type": "normal"}
        ]
    }
}