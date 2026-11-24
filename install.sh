#!/bin/bash
# install.sh — setup system dependencies for wifi_attack on macOS

set -e

echo "[*] installing system dependencies via brew..."
brew update
brew install aircrack-ng hcxtools

echo "[*] creating airport symlink..."
if [ ! -L /usr/local/bin/airport ]; then
    sudo ln -sf /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport /usr/local/bin/airport
    echo "[+] airport symlink created"
else
    echo "[*] airport symlink already exists"
fi

echo "[*] verifying tools..."
for tool in aircrack-ng airodump-ng aireplay-ng airport hcxpcapngtool; do
    if command -v $tool &> /dev/null; then
        echo "    [+] $tool: $(which $tool)"
    else
        echo "    [-] $tool: NOT FOUND"
        exit 1
    fi
done

echo "[*] setting up Python venv (if not exists)..."
VENV_DIR="$(dirname "$0")/.venv"
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo "[+] venv created at $VENV_DIR"
else
    echo "[*] venv already exists"
fi

echo "[*] upgrading pip in venv..."
"$VENV_DIR/bin/python" -m pip install --upgrade pip

echo ""
echo "[+] installation complete!"
echo ""
echo "usage:"
echo "  # generate wordlist"
echo "  $VENV_DIR/bin/python $(dirname "$0")/gen_wordlist.py"
echo ""
echo "  # run attack (needs sudo)"
echo "  sudo $VENV_DIR/bin/python $(dirname "$0")/wifi_attack.py --auto --external"
echo ""
echo "  # with custom options"
echo "  sudo $VENV_DIR/bin/python $(dirname "$0")/wifi_attack.py --auto --external --scan-time 30"