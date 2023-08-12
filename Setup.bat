@echo off

REM Check if Python3 is installed and install if not
python -c "import sys" 2>NUL
if errorlevel 1 (
    echo Python3 is not installed. Installing...
    REM Download the latest Python installer from https://www.python.org/downloads/
    REM Run the installer and make sure to check "Add Python to PATH"
)

REM Check if Python3 pip is installed and install if not
python -m pip --version 2>NUL
if errorlevel 1 (
    echo Python3 pip is not installed. Installing...
    REM Download get-pip.py from https://bootstrap.pypa.io/get-pip.py
    REM Open Command Prompt and run: python get-pip.py
)

REM Check if netaddr Python library is installed and install if not
python -c "import netaddr" 2>NUL
if errorlevel 1 (
    echo netaddr Python library is not installed. Installing...
    python -m pip install netaddr
)

REM Check if scapy Python library is installed and install if not
python -c "import scapy" 2>NUL
if errorlevel 1 (
    echo scapy Python library is not installed. Installing...
    python -m pip install scapy
)

echo Installation completed successfully.
pause
