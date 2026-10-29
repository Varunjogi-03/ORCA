import socket
import struct
from crypt import HybridServer

# Network Configuration
HOST = '0.0.0.0'
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

def start_server():
    server = HybridServer()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen(5)
        print(f"[*] PQC Hybrid Server listening on {HOST}:{PORT}")

        while True:
            conn, addr = server_sock.accept()
            with conn:
                try:
                    # 1. Read the length header, then the client payload
                    raw_len = recv_exact(conn, 4)
                    payload_len = struct.unpack('!I', raw_len)[0]
                    client_payload = recv_exact(conn, payload_len)
                    
                    # 2. Slice the payload into Classical (32B) and PQC (1184B) keys
                    c_x25519_pub = client_payload[:X25519_KEY_SIZE]
                    c_pqc_pub = client_payload[X25519_KEY_SIZE:]
                    
                    # 3. Encapsulate and derive the final AES key
                    s_x25519_pub, s_pqc_cipher, server_aes_key = server.encapsulate_and_derive(c_x25519_pub, c_pqc_pub)
                    
                    # 4. Send the Server Response (X25519 PubKey + PQC Ciphertext)
                    server_response = s_x25519_pub + s_pqc_cipher
                    send_payload(conn, server_response)
                    
                    print(f"[+] Handshake with {addr[0]} complete.")
                    print(f"    Derived AES-256 Key: {server_aes_key.hex()[:16]}...")
                    
                except Exception as e:
                    print(f"[-] Error during handshake: {e}")
                finally:
                    # Regenerate server keys for the next connection to maintain Perfect Forward Secrecy
                    server.cleanup()
                    server = HybridServer()

if __name__ == "__main__":
    start_server()