import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Define the NIST FIPS 203 Standard Algorithm
PQC_ALG = 'ML-KEM-768'

def combine_secrets(classical_secret, pqc_secret):
    """
    Combines the classical and post-quantum shared secrets into a single 
    AES-256-GCM symmetric key using HKDF-SHA256.
    """
    # Concatenate the two secrets to ensure the final key relies on both
    hybrid_secret = classical_secret + pqc_secret
    
    # Use HKDF to securely derive a 32-byte (256-bit) symmetric key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'pqc_hybrid_handshake'
    )
    return hkdf.derive(hybrid_secret)


class HybridClient:
    def __init__(self):
        self.kem = oqs.KeyEncapsulation(PQC_ALG)
        self.x25519_private_key = x25519.X25519PrivateKey.generate()

    def generate_keys(self):
        """Generates classical and PQC keypairs and returns the public keys."""
        # 1. Generate Classical Public Key (32 bytes)
        x25519_pub_bytes = self.x25519_private_key.public_key().public_bytes(
            encoding=x25519.serialization.Encoding.Raw,
            format=x25519.serialization.PublicFormat.Raw
        )
        
        # 2. Generate PQC Public Key (1184 bytes)
        pqc_pub_bytes = self.kem.generate_keypair()
        
        return x25519_pub_bytes, pqc_pub_bytes

    def derive_shared_key(self, server_x25519_pub_bytes, pqc_ciphertext):
        """Decapsulates the server's response to build the final shared AES key."""
        # 1. Derive Classical Secret
        server_x25519_pub = x25519.X25519PublicKey.from_public_bytes(server_x25519_pub_bytes)
        classical_secret = self.x25519_private_key.exchange(server_x25519_pub)
        
        # 2. Decapsulate PQC Secret
        pqc_secret = self.kem.decap_secret(pqc_ciphertext)
        
        # 3. Combine both into final AES key
        return combine_secrets(classical_secret, pqc_secret)

    def cleanup(self):
        """Free the underlying C memory used by liboqs."""
        self.kem.free()


class HybridServer:
    def __init__(self):
        self.kem = oqs.KeyEncapsulation(PQC_ALG)
        self.x25519_private_key = x25519.X25519PrivateKey.generate()

    def encapsulate_and_derive(self, client_x25519_pub_bytes, client_pqc_pub_bytes):
        """Processes client keys, generates server keys, and derives the final AES key."""
        # 1. Generate Server Classical Public Key & Derive Secret
        server_x25519_pub_bytes = self.x25519_private_key.public_key().public_bytes(
            encoding=x25519.serialization.Encoding.Raw,
            format=x25519.serialization.PublicFormat.Raw
        )
        client_x25519_pub = x25519.X25519PublicKey.from_public_bytes(client_x25519_pub_bytes)
        classical_secret = self.x25519_private_key.exchange(client_x25519_pub)
        
        # 2. Encapsulate PQC Secret against Client's PQC Public Key
        pqc_ciphertext, pqc_secret = self.kem.encap_secret(client_pqc_pub_bytes)
        
        # 3. Combine both into final AES key
        final_aes_key = combine_secrets(classical_secret, pqc_secret)
        
        return server_x25519_pub_bytes, pqc_ciphertext, final_aes_key

    def cleanup(self):
        """Free the underlying C memory used by liboqs."""
        self.kem.free()


# --- Local Testing Block ---
if __name__ == "__main__":
    print("[*] Simulating Hybrid Cryptography Locally...")
    
    client = HybridClient()
    server = HybridServer()
    
    # 1. Client generates keys
    c_x25519_pub, c_pqc_pub = client.generate_keys()
    print(f"[+] Client Keys Generated: X25519 ({len(c_x25519_pub)} bytes), ML-KEM ({len(c_pqc_pub)} bytes)")
    
    # 2. Server receives keys, encapsulates, and derives its final key
    s_x25519_pub, s_pqc_cipher, server_aes_key = server.encapsulate_and_derive(c_x25519_pub, c_pqc_pub)
    print(f"[+] Server Response Generated: X25519 ({len(s_x25519_pub)} bytes), ML-KEM Ciphertext ({len(s_pqc_cipher)} bytes)")
    
    # 3. Client receives server response and derives its final key
    client_aes_key = client.derive_shared_key(s_x25519_pub, s_pqc_cipher)
    
    # 4. Verification
    if server_aes_key == client_aes_key:
        print("\n[SUCCESS] Both parties derived the exact same Hybrid AES-256 Key!")
        print(f"Final Key (Hex): {client_aes_key.hex()}")
    else:
        print("\n[FAILED] Keys do not match.")
        
    client.cleanup()
    server.cleanup()