import time
import gc
import psutil
import os
import numpy as np
import pandas as pd
from tabulate import tabulate
from kem_modules import (
    BaseKEM,
    ClassicalX25519KEM,
    ClassicalP256KEM,
    PQCKEM,
    HybridX25519MLKEM
)

def profile_kem(kem: BaseKEM, iterations: int = 1000, warmup: int = 50) -> dict:
    process = psutil.Process(os.getpid())
    
    # Warm-up CPU caches and library initialization
    for _ in range(warmup):
        pk = kem.generate_keypair()
        ct, _ = kem.encap_secret(pk)
        _ = kem.decap_secret(ct)

    keygen_times = np.zeros(iterations, dtype=np.float64)
    encap_times = np.zeros(iterations, dtype=np.float64)
    decap_times = np.zeros(iterations, dtype=np.float64)

    gc.collect()
    gc.disable()  # Disable garbage collection during tight timing loop
    mem_before = process.memory_info().rss

    pk_size = 0
    ct_size = 0
    ss_size = 0

    for i in range(iterations):
        # 1. KeyGen
        t0 = time.perf_counter_ns()
        pk = kem.generate_keypair()
        t1 = time.perf_counter_ns()
        keygen_times[i] = (t1 - t0) / 1e6  # Convert ns to ms

        # 2. Encapsulation
        t0 = time.perf_counter_ns()
        ct, ss_s = kem.encap_secret(pk)
        t1 = time.perf_counter_ns()
        encap_times[i] = (t1 - t0) / 1e6

        # 3. Decapsulation
        t0 = time.perf_counter_ns()
        ss_c = kem.decap_secret(ct)
        t1 = time.perf_counter_ns()
        decap_times[i] = (t1 - t0) / 1e6

        if i == 0:
            assert ss_s == ss_c, f"Verification failure in {kem.name}"
            pk_size = len(pk)
            ct_size = len(ct)
            ss_size = len(ss_c)

    mem_after = process.memory_info().rss
    gc.enable()

    total_times = keygen_times + encap_times + decap_times

    return {
        "Algorithm": kem.name,
        "PK (B)": pk_size,
        "CT (B)": ct_size,
        "Total Payload (B)": pk_size + ct_size,
        "KeyGen Mean (ms)": np.mean(keygen_times),
        "Encap Mean (ms)": np.mean(encap_times),
        "Decap Mean (ms)": np.mean(decap_times),
        "Total Mean (ms)": np.mean(total_times),
        "Total P99 (ms)": np.percentile(total_times, 99),
        "RSS Delta (KB)": max(0.0, (mem_after - mem_before) / 1024.0)
    }

def main():
    iterations = 1000
    print(f"[*] Starting Phase 1 Micro-Benchmark ({iterations} iterations per mechanism)...\n")

    kems_to_test = [
        ClassicalX25519KEM(),
        ClassicalP256KEM(),
        PQCKEM("ML-KEM-512"),
        PQCKEM("ML-KEM-768"),
        PQCKEM("ML-KEM-1024"),
        HybridX25519MLKEM("ML-KEM-512"),
        HybridX25519MLKEM("ML-KEM-768"),
        HybridX25519MLKEM("ML-KEM-1024"),
    ]

    results = []
    for kem in kems_to_test:
        print(f"    -> Benchmarking {kem.name}...")
        stats = profile_kem(kem, iterations=iterations)
        results.append(stats)

    df = pd.DataFrame(results)
    
    print("\n" + "=" * 115)
    print("PHASE 1 BENCHMARK RESULTS: COMPUTATIONAL OVERHEAD & PAYLOAD AMPLIFICATION")
    print("=" * 115)
    print(tabulate(df, headers="keys", tablefmt="github", floatfmt=".4f", showindex=False))
    print("=" * 115)

    csv_filename = "phase1_kem_benchmarks.csv"
    df.to_csv(csv_filename, index=False)
    print(f"\n[+] Exported raw metrics to {csv_filename}")

if __name__ == "__main__":
    main()
