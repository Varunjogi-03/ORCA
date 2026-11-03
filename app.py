import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import socket
import struct
import time
import queue

# Import your working cryptography module
# Make sure your os.environ["LIBOQS_INSTALL_PATH"] is set inside crypto_hybrid.py!
from crypt import HybridClient, HybridServer

HOST = '127.0.0.1'
PORT = 8443
X25519_KEY_SIZE = 32

def recv_exact(sock, num_bytes):
    data = bytearray()
    while len(data) < num_bytes:
        packet = sock.recv(num_bytes - len(data))
        if not packet:
            raise ConnectionError("Socket closed prematurely.")
        data.extend(packet)
    return bytes(data)

def send_payload(sock, payload):
    header = struct.pack('!I', len(payload))
    sock.sendall(header + payload)

class PQCBenchmarkApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hybrid PQC Network Benchmarker")
        self.root.geometry("850x650")
        
        self.server_running = False
        self.log_queue = queue.Queue()
        
        self._build_ui()
        self.root.after(100, self._process_logs)

    def _build_ui(self):
        # --- Control Panel ---
        control_frame = ttk.LabelFrame(self.root, text="Network Controls", padding=(10, 10))
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.btn_start_server = ttk.Button(control_frame, text="1. Start Server Node", command=self.start_server_thread)
        self.btn_start_server.pack(side=tk.LEFT, padx=5)
        
        self.btn_run_client = ttk.Button(control_frame, text="2. Trigger Client Handshake", command=self.run_client_thread, state=tk.DISABLED)
        self.btn_run_client.pack(side=tk.LEFT, padx=5)

        # --- Metrics Dashboard ---
        metrics_frame = ttk.Frame(self.root, padding=(10, 5))
        metrics_frame.pack(fill=tk.X, padx=10)
        
        self.lbl_latency = ttk.Label(metrics_frame, text="Last Latency: -- ms", font=("Helvetica", 12, "bold"))
        self.lbl_latency.pack(side=tk.LEFT, padx=10)

        # --- Client Log Area ---
        ttk.Label(self.root, text="Edge Node (Client) Activity:").pack(anchor=tk.W, padx=10, pady=(10, 0))
        self.client_log = scrolledtext.ScrolledText(self.root, height=10, bg="#1e1e1e", fg="#00ff00", font=("Consolas", 10))
        self.client_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # --- Server Log Area ---
        ttk.Label(self.root, text="Enterprise Server Activity:").pack(anchor=tk.W, padx=10)
        self.server_log = scrolledtext.ScrolledText(self.root, height=10, bg="#1e1e1e", fg="#00ccff", font=("Consolas", 10))
        self.server_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def log(self, target, message):
        """Thread-safe logging using a queue."""
        self.log_queue.put((target, message))

    def _process_logs(self):
        """Processes incoming log messages from background threads."""
        while not self.log_queue.empty():
            target, message = self.log_queue.get()
            if target == "client":
                self.client_log.insert(tk.END, message + "\n")
                self.client_log.see(tk.END)
            elif target == "server":
                self.server_log.insert(tk.END, message + "\n")
                self.server_log.see(tk.END)
            elif target == "latency":
                self.lbl_latency.config(text=f"Last Latency: {message} ms")
        self.root.after(100, self._process_logs)

    # --- Server Thread ---
    def start_server_thread(self):
        self.btn_start_server.config(state=tk.DISABLED)
        self.server_running = True
        threading.Thread(target=self._server_loop, daemon=True).start()
        self.btn_run_client.config(state=tk.NORMAL)

    def _server_loop(self):
        server_engine = HybridServer()
        self.log("server", f"[*] Server started. Listening on {HOST}:{PORT}")
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((HOST, PORT))
            server_sock.listen(5)
            
            while self.server_running:
                try:
                    conn, addr = server_sock.accept()
                    with conn:
                        self.log("server", f"[+] Incoming connection from {addr[0]}")
                        
                        raw_len = recv_exact(conn, 4)
                        payload_len = struct.unpack('!I', raw_len)[0]
                        client_payload = recv_exact(conn, payload_len)
                        
                        c_x25519_pub = client_payload[:X25519_KEY_SIZE]
                        c_pqc_pub = client_payload[X25519_KEY_SIZE:]
                        self.log("server", f"[*] Received {payload_len} bytes (X25519 + ML-KEM)")
                        
                        s_x25519_pub, s_pqc_cipher, server_aes_key = server_engine.encapsulate_and_derive(c_x25519_pub, c_pqc_pub)
                        
                        server_response = s_x25519_pub + s_pqc_cipher
                        send_payload(conn, server_response)
                        self.log("server", f"[*] Sent {len(server_response)} bytes (X25519 + PQC Ciphertext)")
                        self.log("server", f"[SUCCESS] Derived AES Key: {server_aes_key.hex()[:16]}...\n")
                        
                        server_engine.cleanup()
                        server_engine = HybridServer() # Rotate keys for PFS
                except Exception as e:
                    self.log("server", f"[-] Error: {str(e)}")

    # --- Client Thread ---
    def run_client_thread(self):
        self.btn_run_client.config(state=tk.DISABLED)
        threading.Thread(target=self._client_logic, daemon=True).start()

    def _client_logic(self):
        client_engine = HybridClient()
        self.log("client", f"[*] Initiating Hybrid Handshake with {HOST}:{PORT}")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((HOST, PORT))
                
                start_time = time.perf_counter()
                
                # 1. Send Payload
                c_x25519_pub, c_pqc_pub = client_engine.generate_keys()
                client_payload = c_x25519_pub + c_pqc_pub
                send_payload(sock, client_payload)
                self.log("client", f"[*] Sent {len(client_payload)} byte public key payload")
                
                # 2. Receive Response
                raw_len = recv_exact(sock, 4)
                server_payload_len = struct.unpack('!I', raw_len)[0]
                server_response = recv_exact(sock, server_payload_len)
                self.log("client", f"[*] Received {len(server_response)} byte server response")
                
                # 3. Derive Keys
                s_x25519_pub = server_response[:X25519_KEY_SIZE]
                s_pqc_cipher = server_response[X25519_KEY_SIZE:]
                client_aes_key = client_engine.derive_shared_key(s_x25519_pub, s_pqc_cipher)
                
                end_time = time.perf_counter()
                latency_ms = (end_time - start_time) * 1000
                
                self.log("client", f"[SUCCESS] Derived AES Key: {client_aes_key.hex()[:16]}...")
                self.log("latency", f"{latency_ms:.2f}")
                
        except Exception as e:
            self.log("client", f"[-] Connection Error: {str(e)}")
        finally:
            client_engine.cleanup()
            self.root.after(0, lambda: self.btn_run_client.config(state=tk.NORMAL))

if __name__ == "__main__":
    root = tk.Tk()
    app = PQCBenchmarkApp(root)
    root.mainloop()