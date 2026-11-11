import argparse
import asyncio
import json
import math
import os
import socket
import struct
import time
import inspect
import numpy as np
from datetime import datetime
from server import (
    SUITE_REGISTRY,
    HEADER_FMT,
    HEADER_SIZE,
    MSG_CLIENT_HELLO,
    MSG_SERVER_HELLO,
    HOST,
    PORT,
    compute_parallel_metrics,
)

STORAGE_DIR = "key_store/client"


async def send_frame(writer: asyncio.StreamWriter, msg_type: int, suite_id: int, payload: bytes):
    header = struct.pack(HEADER_FMT, msg_type, suite_id, len(payload))
    writer.write(header + payload)
    await writer.drain()


async def recv_frame(reader: asyncio.StreamReader):
    raw_header = await reader.readexactly(HEADER_SIZE)
    msg_type, suite_id, payload_len = struct.unpack(HEADER_FMT, raw_header)
    payload = await reader.readexactly(payload_len)
    return msg_type, suite_id, payload


def run_keygen(kem_instance):
    if hasattr(kem_instance, "generate_keypair"):
        res = kem_instance.generate_keypair()
    else:
        res = kem_instance.keygen()
    return res if isinstance(res, tuple) else (res, None)


def run_decap(kem_instance, ciphertext: bytes, sk):
    decap_fn = (
        getattr(kem_instance, "decapsulate", None)
        or getattr(kem_instance, "decap_secret", None)
        or getattr(kem_instance, "decap", None)
    )
    sig = inspect.signature(decap_fn)
    if len(sig.parameters) >= 2 and sk is not None:
        return decap_fn(ciphertext, sk)
    return decap_fn(ciphertext)


async def parallel_client_precalc(suite_name: str, pk: bytes):
    """
    Runs IN PARALLEL while waiting for ServerHello over the network:
    Pre-calculates ClientHello fragmentation across MTU boundaries and PK bit balance.
    """
    await asyncio.sleep(0)
    ch_total = 260 + len(pk)
    segs_1500 = math.ceil(ch_total / 1460)
    segs_1280 = math.ceil(ch_total / 1240)
    pk_bits = np.unpackbits(np.frombuffer(pk, dtype=np.uint8))
    pk_ones_ratio = float(np.mean(pk_bits))
    print(
        f"  [PARALLEL-CALC] ClientHello ({ch_total}B) -> "
        f"{segs_1500} pkt @1500MTU, {segs_1280} pkt @1280MTU | PK Bit-Balance: {pk_ones_ratio:.4f}"
    )
    return {
        "client_hello_tls_bytes": ch_total,
        "segments_at_1500_mtu": segs_1500,
        "segments_at_1280_mtu": segs_1280,
        "pk_ones_ratio": round(pk_ones_ratio, 4),
    }


def store_client_keys(
    suite_name: str,
    pk: bytes,
    ct: bytes,
    ss: bytes,
    t_keygen_ms: float,
    t_decap_ms: float,
    rtt_ms: float,
    precalc: dict,
    post_metrics: dict,
):
    os.makedirs(STORAGE_DIR, exist_ok=True)
    session_id = f"{int(time.time() * 1000)}"
    crypto_cpu_ms = t_keygen_ms + t_decap_ms
    network_wait_ms = max(0.0, rtt_ms - crypto_cpu_ms)

    data = {
        "session_id": session_id,
        "timestamp": datetime.now().isoformat(),
        "role": "client",
        "suite": suite_name,
        "pk_bytes": len(pk),
        "ct_bytes": len(ct),
        "shared_secret_bytes": len(ss),
        "timings_ms": {
            "keygen_ms": round(t_keygen_ms, 4),
            "decap_ms": round(t_decap_ms, 4),
            "client_crypto_cpu_ms": round(crypto_cpu_ms, 4),
            "network_and_server_wait_ms": round(network_wait_ms, 4),
            "total_handshake_rtt_ms": round(rtt_ms, 4),
        },
        "parallel_precalc": precalc,
        "parallel_telemetry": post_metrics,
        "public_key_hex": pk.hex(),
        "ciphertext_hex": ct.hex(),
        "shared_secret_hex": ss.hex(),
    }
    filepath = os.path.join(STORAGE_DIR, f"client_{session_id}_{suite_name}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return filepath


async def execute_handshake(suite_id: int):
    if suite_id not in SUITE_REGISTRY:
        print(f"[!] Invalid Suite ID {suite_id}.")
        return

    suite_name, factory = SUITE_REGISTRY[suite_id]
    kem_instance = factory()
    loop = asyncio.get_running_loop()

    print("-" * 75)
    print(f"[*] Connecting to {HOST}:{PORT} | Suite [{suite_id}]: {suite_name}")

    t_start = time.perf_counter_ns()
    reader, writer = await asyncio.open_connection(HOST, PORT)
    sock = writer.get_extra_info("socket")
    if sock is not None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    # 1. Generate Client Keypair
    t0 = time.perf_counter_ns()
    pk, sk = await loop.run_in_executor(None, run_keygen, kem_instance)
    t_keygen_ms = (time.perf_counter_ns() - t0) / 1e6
    print(f"  [1] KeyGen Complete | PK: {len(pk)}B ({t_keygen_ms:.3f} ms)")

    # 2. Send ClientHello and run parallel client pre-calculation while awaiting ServerHello
    await send_frame(writer, MSG_CLIENT_HELLO, suite_id, pk)

    recv_coro = recv_frame(reader)
    precalc_coro = parallel_client_precalc(suite_name, pk)
    (msg_type, srv_suite_id, ciphertext), precalc = await asyncio.gather(recv_coro, precalc_coro)

    if msg_type != MSG_SERVER_HELLO:
        raise RuntimeError(f"Unexpected response frame type: {msg_type}")

    # 3. Decapsulate Shared Secret
    t1 = time.perf_counter_ns()
    shared_secret = await loop.run_in_executor(None, run_decap, kem_instance, ciphertext, sk)
    t_decap_ms = (time.perf_counter_ns() - t1) / 1e6
    total_rtt_ms = (time.perf_counter_ns() - t_start) / 1e6

    # 4. Compute full NIST/MTU telemetry & store session JSON
    post_metrics = await loop.run_in_executor(
        None, compute_parallel_metrics, sock, len(pk), len(ciphertext), shared_secret, ciphertext
    )
    saved_path = await loop.run_in_executor(
        None,
        store_client_keys,
        suite_name,
        pk,
        ciphertext,
        shared_secret,
        t_keygen_ms,
        t_decap_ms,
        total_rtt_ms,
        precalc,
        post_metrics,
    )

    nist = post_metrics["nist_sp800_22"]
    print(f"  [2] ServerHello Recv| CT: {len(ciphertext)}B | Decap: {t_decap_ms:.3f} ms | Total RTT: {total_rtt_ms:.3f} ms")
    print(f"  [3] NIST Entropy    | Monobit p={nist['monobit_p_value']} | Runs p={nist['runs_p_value']} | Shannon={nist['payload_shannon_entropy_bpb']} bpb")
    print(f"  [OK] Shared Secret  : {shared_secret.hex()[:32]}...")
    print(f"  [SAVED] {saved_path}")

    writer.close()
    await writer.wait_closed()


async def main():
    parser = argparse.ArgumentParser(description="ORCA Async PQC/Hybrid Client")
    parser.add_argument("--suite", type=int, default=0, help="Suite ID (1-6), or 0 for all")
    args = parser.parse_args()

    if args.suite == 0:
        print("[*] Running full handshake + parallel telemetry sweep across all 6 KEM suites...")
        for sid in SUITE_REGISTRY:
            await execute_handshake(sid)
    else:
        await execute_handshake(args.suite)


if __name__ == "__main__":
    asyncio.run(main())
