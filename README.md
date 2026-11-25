# ORCA: Post-Quantum Cryptography Benchmark Suite

ORCA is a research and demonstration project for comparing classical, post-quantum, and hybrid key-encapsulation mechanisms (KEMs). It includes local cryptographic demonstrations, a framed TCP client/server, a Streamlit dashboard, and command-line benchmark utilities.

> **Scope:** This repository is a prototype and benchmark suite, not a transparent network-layer security service or a production TLS implementation. Its custom TCP framing does not provide authentication, a complete secure channel, or protection for arbitrary application traffic.

## What is in this repository?

### `orca-main/` — primary suite

- `kem_modules.py` implements a common KEM interface for X25519, NIST P-256, liboqs post-quantum KEMs (ML-KEM/Kyber), and an X25519 + ML-KEM hybrid.
- `server.py` runs an asynchronous TCP server on `127.0.0.1:9443`. It accepts a client public key, encapsulates a shared secret, returns the ciphertext, calculates packet/MTU and randomness telemetry, and writes session records under `key_store/server/`.
- `client.py` runs the matching handshake and writes records under `key_store/client/`.
- `main.py` is a Streamlit dashboard for local KEM handshakes and AES-GCM demonstrations, microbenchmarks, MTU/latency modeling, randomness visualizations, and stored session records.
- `test_kem.py`, `benchmark_phase1.py`, and `verify_env.py` check KEM agreement, measure operation costs, and inspect the liboqs environment.
- `setup_env.sh` builds liboqs and installs a Python environment on Debian/Ubuntu systems.

### Root-level prototype

- `crypt.py`, `server.py`, and `client.py` provide a simpler ML-KEM-768 + X25519 handshake on TCP port `8443`.
- `app.py` provides a Tkinter interface to that handshake and reports handshake latency.
- `phase 2/benchmark-kem.py` is an additional liboqs timing script.
- `network/orca.py` is currently empty.

The root prototype and `orca-main` are separate experiments: their scripts use different ports, protocols, and crypto wrappers. Run commands from the relevant directory.

## Requirements

The primary suite needs Python 3, a working liboqs shared library with a supported KEM enabled, and the Python packages in `orca-main/requirements.txt`. The setup helper targets Debian/Ubuntu and uses `sudo` to install system packages and liboqs. It clones liboqs from its `main` branch, so exact library contents can change over time.

## Setup (`orca-main`)

From the repository root:

```bash
cd orca-main
chmod +x setup_env.sh
./setup_env.sh
source .venv/bin/activate
```

The script builds and installs liboqs under `/usr/local`, creates `.venv`, and installs the project dependencies. If you already have a compatible liboqs installation, you can instead create a virtual environment and install the pinned requirements:

```bash
cd orca-main
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

That alternative assumes the liboqs C library is installed and discoverable by `liboqs-python`. Verify the environment with:

```bash
python verify_env.py
```

## Run the primary application

Open two terminals. In both, enter `orca-main` and activate the virtual environment.

Terminal 1 — start the TCP server:

```bash
cd orca-main
source .venv/bin/activate
python server.py
```

Terminal 2 — launch the dashboard:

```bash
cd orca-main
source .venv/bin/activate
streamlit run main.py
```

Streamlit prints the local URL to open in a browser. The dashboard’s live client/server tab requires the server to be running. It can launch a single suite or a full sweep; session JSON files are created in `orca-main/key_store/client/` and `orca-main/key_store/server/` relative to the process working directory.

You can also run the CLI client directly while the server is running:

```bash
python client.py --help
python client.py --suite 1
python client.py --suite 0   # all configured suites
```

Use `python server.py` and `python client.py` from `orca-main`; the service binds to loopback (`127.0.0.1`) by default.

## Other commands

From `orca-main`, with the environment activated:

```bash
python test_kem.py           # KEM shared-secret agreement checks
python benchmark_phase1.py   # 1,000-iteration operation benchmark; writes CSV
```

The dashboard also provides interactive microbenchmarks and visualizations. Results depend on the machine, Python build, and liboqs build; benchmark figures are measurements, not guarantees.

## Run the root-level prototype

This uses the separate root-level `crypt.py` implementation and port `8443`. Install compatible `liboqs-python` and `cryptography` dependencies and ensure liboqs is available. In separate terminals from the repository root:

```bash
python server.py
```

```bash
python client.py
```

To use its Tkinter interface instead of the CLI client:

```bash
python app.py
```

The GUI starts its own server on `127.0.0.1:8443`; do not start the root-level `server.py` at the same time. Tkinter must be available in your Python installation.

## Protocol and security notes

The `orca-main` protocol sends a KEM public key and ciphertext in custom length-prefixed frames. It derives KEM shared secrets and demonstrates AES-256-GCM in the dashboard’s local demo, but the live TCP protocol does not use that key to encrypt application payloads. The root prototype derives a combined 32-byte key using HKDF-SHA256 but also does not implement an authenticated encrypted application-data channel. Neither protocol authenticates peers or should be exposed to untrusted networks or used to protect real application traffic.

The “NIST SP 800-22” views are limited statistical checks/visualizations over generated data; they are not a formal certification of a cryptographic implementation or random-number generator.
