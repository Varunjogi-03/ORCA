import socket
import struct
import time
from crypt import HybridClient

# Network Configuration
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

def run_client():
    client = HybridClient()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        print(f"[*] Connecting to {HOST}:{PORT}...")
        sock.connect((HOST, PORT))
        
        # Start Stopwatch
        start_time = time.perf_counter()

        # 1. Generate Hybrid Keys and send them
        c_x25519_pub, c_pqc_pub = client.generate_keys()
        client_payload = c_x25519_pub + c_pqc_pub
        send_payload(sock, client_payload)
        
        # 2. Wait for Server Response
        raw_len = recv_exact(sock, 4)
        server_payload_len = struct.unpack('!I', raw_len)[0]
        server_response = recv_exact(sock, server_payload_len)
        
        # 3. Slice Server Response into Classical Key and PQC Ciphertext
        s_x25519_pub = server_response[:X25519_KEY_SIZE]
        s_pqc_cipher = server_response[X25519_KEY_SIZE:]
        
        # 4. Decapsulate and derive final AES key
        client_aes_key = client.derive_shared_key(s_x25519_pub, s_pqc_cipher)
        
        # Stop Stopwatch
        end_time = time.perf_counter()
        
        print(f"[+] Hybrid Handshake Latency: {(end_time - start_time) * 1000:.2f} ms")
        print(f"    Derived AES-256 Key: {client_aes_key.hex()[:16]}...")
        
    client.cleanup()

if __name__ == "__main__":
    run_client()