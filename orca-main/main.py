import os
import time
import math
import socket
import struct
import threading
import inspect
import psutil
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import oqs
import kem_modules

st.set_page_config(page_title="ORCA: PQC Migration Benchmark", layout="wide")

# Custom compact styling for metric cards
st.markdown("""
<style>
div[data-testid="stMetricValue"] { font-size: 1.4rem; }
</style>
""", unsafe_allow_html=True)

st.title("ORCA: Hybrid Post-Quantum Cryptography Migration Suite")

# -------------------------------------------------------------------------
# AUTO-DISCOVER KEM CLASSES FROM kem_modules.py
# -------------------------------------------------------------------------
KEM_CLASSES = {
    name: cls
    for name, cls in inspect.getmembers(kem_modules, inspect.isclass)
    if cls.__module__ == "kem_modules" and not inspect.isabstract(cls) and name != "BaseKEM"
}

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("liboqs C Engine", oqs.oqs_version())
col2.metric("Active KEM Modules", len(KEM_CLASSES))
col3.metric("Classical Baseline", "X25519 / P-256")
col4.metric("NIST PQC Standard", "FIPS 203 (ML-KEM)")
col5.metric("AEAD Data Cipher", "AES-256-GCM")

tab1, tab2, tab3, tab4 = st.tabs([
    "1. Handshake & AES-GCM Tunnel",
    "2. Micro-Benchmark & Tail Distributions",
    "3. MTU Fragmentation & Real TCP Loopback",
    "4. NIST SP 800-22 & Bit-Noise Matrix"
])


# -------------------------------------------------------------------------
# UNIVERSAL KEM HELPER
# -------------------------------------------------------------------------
def run_kem_exchange(kem, corrupt_ct: bool = False):
    """Executes KeyGen, Encap, and Decap and returns payloads + timings in ms."""
    t0 = time.perf_counter_ns()
    if hasattr(kem, "generate_keypair"):
        res = kem.generate_keypair()
    elif hasattr(kem, "keygen"):
        res = kem.keygen()
    else:
        raise AttributeError(f"Cannot find keygen method on {type(kem).__name__}")
    t_keygen = (time.perf_counter_ns() - t0) / 1e6

    if isinstance(res, tuple):
        pk, sk = res[0], res[1]
    else:
        pk, sk = res, None

    t0 = time.perf_counter_ns()
    encap_fn = (
        getattr(kem, "encapsulate", None)
        or getattr(kem, "encap_secret", None)
        or getattr(kem, "encap", None)
    )
    ct, ss_server = encap_fn(pk)
    t_encap = (time.perf_counter_ns() - t0) / 1e6

    if corrupt_ct:
        ct_bytearray = bytearray(ct)
        ct_bytearray[-1] ^= 0x01
        ct = bytes(ct_bytearray)

    t0 = time.perf_counter_ns()
    decap_fn = (
        getattr(kem, "decapsulate", None)
        or getattr(kem, "decap_secret", None)
        or getattr(kem, "decap", None)
    )
    sig = inspect.signature(decap_fn)
    if len(sig.parameters) >= 2 and sk is not None:
        ss_client = decap_fn(ct, sk)
    else:
        ss_client = decap_fn(ct)
    t_decap = (time.perf_counter_ns() - t0) / 1e6

    return pk, ct, ss_server, ss_client, t_keygen, t_encap, t_decap


@st.cache_data
def get_baseline_kem_profiles():
    """Cached baseline inspection so Tab 3 sliders respond instantaneously."""
    profiles = []
    for name, cls in KEM_CLASSES.items():
        try:
            inst = cls()
            pk, ct, ss_s, _, t_kg, t_enc, t_dec = run_kem_exchange(inst, False)
            profiles.append({
                "Algorithm": name,
                "pk_bytes": len(pk),
                "ct_bytes": len(ct),
                "ss_bytes": len(ss_s),
                "cpu_ms": t_kg + t_enc + t_dec
            })
        except Exception:
            continue
    return profiles


# =========================================================================
# TAB 1: LIVE HANDSHAKE & END-TO-END AES-256-GCM PAYLOAD TUNNEL
# =========================================================================
with tab1:
    st.subheader("Interactive Key Encapsulation + Authenticated AES-256-GCM Tunnel")

    c_left, c_right = st.columns([2, 1])
    with c_left:
        selected_class_name = st.radio(
            "Select KEM Class:",
            list(KEM_CLASSES.keys()),
            horizontal=True
        )
        test_message = st.text_input(
            "Application Payload to Encrypt with Derived Shared Secret (AES-256-GCM):",
            value="CONFIDENTIAL: Post-Quantum Hybrid TLS 1.3 Migration Telemetry Packet #042"
        )
    with c_right:
        st.markdown("**Fault Injection Controls**")
        corrupt_ct = st.checkbox("Flip 1 Bit in KEM Ciphertext (Test Implicit Rejection)")

    if st.button("Execute Handshake & Transmit Encrypted Payload", type="primary"):
        kem_cls = KEM_CLASSES[selected_class_name]
        kem_instance = kem_cls()

        try:
            pk, ct, ss_server, ss_client, t_keygen, t_encap, t_decap = run_kem_exchange(
                kem_instance, corrupt_ct
            )

            k1, k2, k3 = st.columns(3)
            k1.info(f"**1. Client Public Key**\n\nSize: `{len(pk)} B` | Time: `{t_keygen:.3f} ms`\n\n`{pk[:32].hex()}...`")
            k2.warning(f"**2. Server Ciphertext**\n\nSize: `{len(ct)} B` | Time: `{t_encap:.3f} ms`\n\n`{ct[:32].hex()}...`")

            if ss_client == ss_server:
                k3.success(
                    f"**3. Shared Secret Match!**\n\nSize: `{len(ss_client)} B` | Decap: `{t_decap:.3f} ms`\n\n"
                    f"Server: `{ss_server.hex()[:28]}...`\n\nClient: `{ss_client.hex()[:28]}...`"
                )
            else:
                k3.error(
                    f"**3. Shared Secret Mismatch (Implicit Rejection!)**\n\n"
                    f"Server: `{ss_server.hex()[:28]}...`\n\nClient: `{ss_client.hex()[:28]}...`"
                )

            # End-to-End AES-256-GCM Tunnel Test
            st.markdown("#### Step 4: Symmetric AEAD Tunnel Verification (`AES-256-GCM`)")
            nonce = os.urandom(12)
            server_aead = AESGCM(ss_server[:32])
            encrypted_payload = server_aead.encrypt(nonce, test_message.encode("utf-8"), b"ORCA-TLS13-AAD")

            try:
                client_aead = AESGCM(ss_client[:32])
                decrypted_bytes = client_aead.decrypt(nonce, encrypted_payload, b"ORCA-TLS13-AAD")
                st.success(
                    f"**AEAD Decryption Verified!** (Ciphertext: `{encrypted_payload.hex()[:48]}...`)\n\n"
                    f"**Recovered Plaintext:** `{decrypted_bytes.decode('utf-8')}`"
                )
            except Exception:
                st.error(
                    "**AES-256-GCM Authentication Tag Verification Failed (`InvalidTag`)!** "
                    "Because the KEM ciphertext was tampered with, the client derived a pseudorandom fallback key "
                    "and blocked the forged channel."
                )
        except Exception as e:
            st.error(f"Handshake Error: `{type(e).__name__}: {e}`")


# =========================================================================
# TAB 2: MICRO-BENCHMARK RUNNER WITH PLOTLY DISTRIBUTIONS
# =========================================================================
with tab2:
    st.subheader("Phase 1 Cryptographic Micro-Benchmarks & Latency Distributions")

    col_cfg1, col_cfg2 = st.columns([2, 1])
    with col_cfg1:
        selected_bench_kems = st.multiselect(
            "Select KEM Modules:",
            list(KEM_CLASSES.keys()),
            default=list(KEM_CLASSES.keys())
        )
    with col_cfg2:
        iterations = st.slider("Iterations per Module:", min_value=50, max_value=2000, value=300, step=50)

    if st.button("Run Full Benchmark & Distribution Analysis", type="primary"):
        process = psutil.Process(os.getpid())
        progress_bar = st.progress(0)
        summary_rows = []
        raw_samples = []

        for idx, name in enumerate(selected_bench_kems):
            cls = KEM_CLASSES[name]
            instance = cls()
            run_kem_exchange(instance, False)  # Warm-up

            rss_before = process.memory_info().rss / (1024 * 1024)
            t_kg_list, t_enc_list, t_dec_list = [], [], []
            pk_len, ct_len, ss_len = 0, 0, 0

            for _ in range(iterations):
                pk, ct, ss_s, _, t_kg, t_enc, t_dec = run_kem_exchange(instance, False)
                t_kg_list.append(t_kg)
                t_enc_list.append(t_enc)
                t_dec_list.append(t_dec)
                tot = t_kg + t_enc + t_dec
                raw_samples.append({"Algorithm": name, "Total Latency (ms)": tot})
                pk_len, ct_len, ss_len = len(pk), len(ct), len(ss_s)

            rss_after = process.memory_info().rss / (1024 * 1024)
            total_list = [a + b + c for a, b, c in zip(t_kg_list, t_enc_list, t_dec_list)]

            summary_rows.append({
                "Algorithm": name,
                "Public Key (B)": pk_len,
                "Ciphertext (B)": ct_len,
                "Total Wire (B)": pk_len + ct_len,
                "KeyGen Mean (ms)": round(float(np.mean(t_kg_list)), 4),
                "Encap Mean (ms)": round(float(np.mean(t_enc_list)), 4),
                "Decap Mean (ms)": round(float(np.mean(t_dec_list)), 4),
                "Total Mean (ms)": round(float(np.mean(total_list)), 4),
                "Total P50 (ms)": round(float(np.percentile(total_list, 50)), 4),
                "Total P95 (ms)": round(float(np.percentile(total_list, 95)), 4),
                "Total P99 (ms)": round(float(np.percentile(total_list, 99)), 4),
                "StdDev (ms)": round(float(np.std(total_list)), 4),
                "Process RSS (MB)": round(rss_after, 2),
            })
            progress_bar.progress((idx + 1) / len(selected_bench_kems))

        st.session_state["df_bench"] = pd.DataFrame(summary_rows)
        st.session_state["df_raw_samples"] = pd.DataFrame(raw_samples)

    if "df_bench" in st.session_state:
        df_bench = st.session_state["df_bench"]
        df_raw = st.session_state["df_raw_samples"]
        st.dataframe(df_bench, use_container_width=True)

        p1, p2 = st.columns(2)
        with p1:
            fig_ops = px.bar(
                df_bench,
                x="Algorithm",
                y=["KeyGen Mean (ms)", "Encap Mean (ms)", "Decap Mean (ms)"],
                title="Stacked Cryptographic Operation Time (ms)",
                barmode="stack"
            )
            st.plotly_chart(fig_ops, use_container_width=True)

        with p2:
            fig_box = px.box(
                df_raw,
                x="Algorithm",
                y="Total Latency (ms)",
                color="Algorithm",
                title="Latency Distribution & Tail Outliers (Box Plot)",
                points="outliers"
            )
            st.plotly_chart(fig_box, use_container_width=True)

        csv_data = df_bench.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download Benchmark Table (results_phase1.csv)",
            data=csv_data,
            file_name="results_phase1.csv",
            mime="text/csv"
        )


# =========================================================================
# TAB 3: MTU FRAGMENTATION & REAL LOOPBACK TCP BENCHMARK
# =========================================================================
def run_real_tcp_handshake(kem_cls, mss_limit: int, trials: int = 30) -> float:
    """Runs an actual TCP socket loopback handshake over 127.0.0.1 with TCP_MAXSEG."""
    kem_server = kem_cls()
    kem_client = kem_cls()
    timings = []

    for _ in range(trials):
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, mss_limit)
        except OSError:
            pass
        srv_sock.bind(("127.0.0.1", 0))
        port = srv_sock.getsockname()[1]
        srv_sock.listen(1)

        def server_worker():
            conn, _ = srv_sock.accept()
            # Read 4-byte length header + ClientHello PK
            raw_len = conn.recv(4)
            pk_len = struct.unpack("!I", raw_len)[0]
            pk_buf = b""
            while len(pk_buf) < pk_len:
                pk_buf += conn.recv(pk_len - len(pk_buf))

            # Encapsulate and send back ServerHello CT
            encap_fn = getattr(kem_server, "encapsulate", None) or getattr(kem_server, "encap_secret", None)
            ct, _ = encap_fn(pk_buf)
            conn.sendall(struct.pack("!I", len(ct)) + ct)
            conn.close()

        t_srv = threading.Thread(target=server_worker, daemon=True)
        t_srv.start()

        t0 = time.perf_counter_ns()
        cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            cli_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, mss_limit)
        except OSError:
            pass
        cli_sock.connect(("127.0.0.1", port))

        pk, _, _, _, _, _, _ = run_kem_exchange(kem_client, False)
        cli_sock.sendall(struct.pack("!I", len(pk)) + pk)

        raw_ct_len = cli_sock.recv(4)
        ct_len = struct.unpack("!I", raw_ct_len)[0]
        ct_buf = b""
        while len(ct_buf) < ct_len:
            ct_buf += cli_sock.recv(ct_len - len(ct_buf))

        cli_sock.close()
        t_srv.join()
        srv_sock.close()
        timings.append((time.perf_counter_ns() - t0) / 1e6)

    return float(np.median(timings))


with tab3:
    st.subheader("TLS 1.3 MTU Fragmentation Visualizer & Live TCP Socket Testbed")

    s1, s2, s3, s4 = st.columns(4)
    with s1:
        mtu = st.slider("Network MTU (Bytes):", 1280, 1500, 1500, 10)
    with s2:
        rtt_ms = st.slider("Simulated WAN RTT (ms):", 5, 200, 35, 5)
    with s3:
        loss_pct = st.slider("Simulated Packet Loss (%):", 0.0, 5.0, 1.0, 0.25)
    with s4:
        auth_mode = st.selectbox("Server Auth Cert:", ["Classical ECDSA (~400 B)", "Post-Quantum ML-DSA-65 (~5,245 B)"])

    mss = mtu - 40
    client_hello_base = 260
    server_hello_base = 220
    auth_bytes = 5245 if "ML-DSA" in auth_mode else 400
    loss_rate = loss_pct / 100.0

    profiles = get_baseline_kem_profiles()
    mtu_rows = []
    for prof in profiles:
        pk_size = prof["pk_bytes"]
        ct_size = prof["ct_bytes"]
        cpu_ms = prof["cpu_ms"]

        ch_total = client_hello_base + pk_size
        sh_total = server_hello_base + ct_size + auth_bytes
        c_segs = math.ceil(ch_total / mss)
        s_segs = math.ceil(sh_total / mss)
        tot_segs = c_segs + s_segs

        drop_prob = 1.0 - ((1.0 - loss_rate) ** tot_segs)
        p50_ms = rtt_ms + cpu_ms + (0.15 * rtt_ms if c_segs > 1 else 0.0)
        p99_ms = p50_ms + (rtt_ms * 2.2 * (1.0 + drop_prob * 8.0) if drop_prob > 0.01 else rtt_ms * 0.15)

        mtu_rows.append({
            "Algorithm": prof["Algorithm"],
            "ClientHello Total (B)": ch_total,
            "Server Flight Total (B)": sh_total,
            "Client TCP Segments": c_segs,
            "Server TCP Segments": s_segs,
            "Total Packets": tot_segs,
            "ClientHello Fragmented?": "FRAGMENTED" if c_segs > 1 else "SINGLE PACKET",
            "Loss Probability (%)": round(drop_prob * 100, 2),
            "P50 Handshake (ms)": round(p50_ms, 2),
            "P99 Tail Latency (ms)": round(p99_ms, 2),
        })

    df_mtu = pd.DataFrame(mtu_rows)
    st.dataframe(df_mtu, use_container_width=True)

    g1, g2 = st.columns(2)
    with g1:
        fig_mss = px.bar(
            df_mtu,
            x="Algorithm",
            y="ClientHello Total (B)",
            color="ClientHello Fragmented?",
            color_discrete_map={"SINGLE PACKET": "#2ecc71", "FRAGMENTED": "#e74c3c"},
            title=f"ClientHello Wire Size vs. Active TCP MSS Boundary ({mss} B)"
        )
        fig_mss.add_hline(
            y=mss,
            line_dash="dash",
            line_color="red",
            annotation_text=f"TCP MSS Limit ({mss} B) - Exceeding splits packet!",
            annotation_position="top left"
        )
        st.plotly_chart(fig_mss, use_container_width=True)

    with g2:
        fig_lat = px.bar(
            df_mtu,
            x="Algorithm",
            y=["P50 Handshake (ms)", "P99 Tail Latency (ms)"],
            barmode="group",
            title=f"P50 vs. P99 Tail Latency (@ {rtt_ms}ms RTT, {loss_pct}% Loss)"
        )
        st.plotly_chart(fig_lat, use_container_width=True)

    st.divider()
    st.markdown("#### Phase 2 Preview: Real Kernel Socket Loopback Test (`127.0.0.1` with `TCP_MAXSEG`)")
    if st.button("Execute Real TCP Socket Handshakes (30 Trials per Algorithm)"):
        sock_rows = []
        for name, cls in KEM_CLASSES.items():
            med_ms = run_real_tcp_handshake(cls, mss_limit=mss, trials=30)
            sock_rows.append({
                "Algorithm": name,
                "Configured TCP_MAXSEG (B)": mss,
                "Median Real Socket Handshake (ms)": round(med_ms, 3)
            })
        st.dataframe(pd.DataFrame(sock_rows), use_container_width=True)


# =========================================================================
# TAB 4: NIST SP 800-22 ENTROPY & 2D BIT-NOISE VISUALIZER
# =========================================================================
with tab4:
    st.subheader("NIST SP 800-22 Statistical Randomness Suite & 2D Bit-Noise Matrix")

    c_n1, c_n2 = st.columns([2, 1])
    with c_n1:
        inspect_alg = st.selectbox("Select Algorithm for Visual Bit-Plane Inspection:", list(KEM_CLASSES.keys()))
    with c_n2:
        num_secrets = st.slider("Consecutive Handshakes to Concatenate:", 128, 1024, 256, 64)

    if st.button("Run NIST SP 800-22 Battery & Generate Bit-Matrix", type="primary"):
        nist_rows = []
        selected_bits = None

        for name, cls in KEM_CLASSES.items():
            inst = cls()
            chunks = [run_kem_exchange(inst, False)[2] for _ in range(num_secrets)]
            raw_bytes = b"".join(chunks)
            bits = np.unpackbits(np.frombuffer(raw_bytes, dtype=np.uint8))
            n = len(bits)

            if name == inspect_alg:
                selected_bits = bits

            # 1. Monobit Test
            s_n = np.sum(2 * bits.astype(np.int64) - 1)
            p_mono = math.erfc((abs(s_n) / math.sqrt(n)) / math.sqrt(2.0))

            # 2. Block Frequency (M=128)
            num_b = n // 128
            blocks = bits[:num_b * 128].reshape((num_b, 128))
            prop = np.sum(blocks, axis=1) / 128.0
            chi_sq = 4.0 * 128.0 * np.sum((prop - 0.5) ** 2)
            # Normal approximation if scipy is absent
            p_block = math.erfc(abs(chi_sq - num_b) / math.sqrt(2.0 * num_b))

            # 3. Runs Test
            pi = float(np.sum(bits)) / n
            v_obs = float(np.sum(bits[:-1] != bits[1:]) + 1)
            p_runs = math.erfc(
                abs(v_obs - 2.0 * n * pi * (1.0 - pi)) / (2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi))
            )

            # 4. Spectral DFT Test
            x_dft = 2 * bits.astype(np.float64) - 1.0
            m_dft = np.abs(np.fft.fft(x_dft)[: n // 2])
            t_thresh = math.sqrt(math.log(1.0 / 0.05) * n)
            n_0 = 0.95 * n / 2.0
            n_1 = float(np.sum(m_dft < t_thresh))
            d_stat = (n_1 - n_0) / math.sqrt(n * 0.95 * 0.05 / 4.0)
            p_dft = math.erfc(abs(d_stat) / math.sqrt(2.0))

            passed_all = all(p >= 0.01 for p in [p_mono, p_block, p_runs, p_dft])
            nist_rows.append({
                "Algorithm": name,
                "Total Bits": n,
                "Ones Ratio": round(pi, 5),
                "01. Monobit (p)": round(p_mono, 4),
                "02. Block Freq (p)": round(p_block, 4),
                "03. Runs Test (p)": round(p_runs, 4),
                "06. Spectral DFT (p)": round(p_dft, 4),
                "SP 800-22 Verdict (α=0.01)": "PASS" if passed_all else "FAIL"
            })

        st.dataframe(pd.DataFrame(nist_rows), use_container_width=True)

        if selected_bits is not None:
            side = int(math.isqrt(len(selected_bits)))
            matrix_2d = selected_bits[: side * side].reshape((side, side))
            fig_heat = px.imshow(
                matrix_2d,
                color_continuous_scale="Greys",
                title=f"2D Bit-Plane Entropy Bitmap: {inspect_alg} ({side}x{side} bits)"
            )
            st.plotly_chart(fig_heat, use_container_width=True)
