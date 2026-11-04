from kem_modules import (
    ClassicalX25519KEM,
    ClassicalP256KEM,
    PQCKEM,
    HybridX25519MLKEM
)

def run_tests():
    mechanisms = [
        ClassicalX25519KEM(),
        ClassicalP256KEM(),
        PQCKEM("ML-KEM-512"),
        PQCKEM("ML-KEM-768"),
        PQCKEM("ML-KEM-1024"),
        HybridX25519MLKEM("ML-KEM-768")
    ]

    print("[*] Running correctness tests across all KEM modules...")
    for kem in mechanisms:
        # Client generates keypair
        pk = kem.generate_keypair()
        
        # Server encapsulates secret using client's public key
        ct, ss_server = kem.encap_secret(pk)
        
        # Client decapsulates ciphertext
        ss_client = kem.decap_secret(ct)

        assert ss_server == ss_client, f"Secret mismatch in {kem.name}!"
        assert len(ss_server) == 32, f"Expected 32-byte secret in {kem.name}, got {len(ss_server)}"
        
        print(f"  [+] {kem.name:<26} | PK: {len(pk):>4}B | CT: {len(ct):>4}B | Secret Match: OK")

    print("[+] All Phase 1 KEM modules passed verification!")

if __name__ == "__main__":
    run_tests()
