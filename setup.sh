#!/bin/bash

# Check if Python3 is installed and install if not
if ! type -P python3 &>/dev/null; then
    echo "Python3 is not installed. Installing..."
    sudo apt update
    sudo apt install python3
fi

# Check if Python3 pip is installed and install if not
if ! python3 -m pip &>/dev/null; then
    echo "Python3 pip is not installed. Installing..."
    sudo apt update
    sudo apt install python3-pip -y
fi

# Check if netaddr Python library is installed and install if not
if ! python3 -c "import netaddr" &>/dev/null; then
    echo "netaddr Python library is not installed. Installing..."
    sudo -H python3 -m pip install -U netaddr
fi

# Check if scapy Python library is installed and install if not
if ! python3 -c "from scapy.all import *" &>/dev/null; then
    echo "scapy Python library is not installed. Installing..."
    sudo -H python3 -m pip install -U scapy
fi

echo "Installation completed successfully."
