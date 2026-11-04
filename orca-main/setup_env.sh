#!/usr/bin/env bash
set -e

echo "[*] Installing system build dependencies..."
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build git libssl-dev python3-venv python3-pip

# 1. Build and install liboqs C library with shared library enabled
if [ ! -d "liboqs" ]; then
    echo "[*] Cloning Open Quantum Safe (liboqs)..."
    git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git
fi

echo "[*] Building liboqs shared library..."
cmake -S liboqs -B liboqs/build -GNinja \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_USE_OPENSSL=ON \
    -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build liboqs/build
sudo cmake --install liboqs/build
sudo ldconfig

# 2. Setup Python virtual environment and install dependencies
echo "[*] Setting up Python virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install cryptography psutil numpy pandas tabulate
pip install git+https://github.com/open-quantum-safe/liboqs-python.git

echo "[+] Phase 1 environment setup complete! Run: source .venv/bin/activate"
