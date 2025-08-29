#!/bin/bash
set -e

echo "[*] Checking if OVS service exists..."
if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files | grep -q openvswitch-switch.service; then
        echo "[*] Starting Open vSwitch via systemctl..."
        sudo systemctl start openvswitch-switch
        sudo systemctl enable openvswitch-switch
    else
        echo "[!] No systemd service found. Trying manual start..."
    fi
else
    echo "[*] systemctl not found, trying service..."
    sudo service openvswitch-switch start || true
fi

# If ovs-vsctl still fails, start ovsdb-server manually
echo "[*] Checking ovsdb-server socket..."
if [ ! -S /var/run/openvswitch/db.sock ]; then
    echo "[!] ovsdb-server not running. Starting manually..."
    sudo mkdir -p /var/run/openvswitch
    sudo ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema || true
    sudo ovsdb-server \
        --remote=punix:/var/run/openvswitch/db.sock \
        --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
        --pidfile --detach
    sudo ovs-vsctl --no-wait init
    sudo ovs-vswitchd --pidfile --detach
fi

echo "[*] Verifying setup..."
sudo ovs-vsctl show

