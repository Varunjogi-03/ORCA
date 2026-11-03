import time
import oqs
import secrets

def benchmark_kem_operations(kem_name: str, iterations: int = 1000):
    with oqs.KeyEncapsulation(kem_name) as client_kem:
        with oqs.KeyEncapsulation(kem_name) as server_kem:
            # Measure Key Generation
            t0 = time.perf_counter()
            for _ in range(iterations):
                client_pk = client_kem.generate_keypair()
            t_keygen = (time.perf_counter() - t0) / iterations

            # Measure Encapsulation
            t0 = time.perf_counter()
            for _ in range(iterations):
                ciphertext, shared_secret_s = server_kem.encap_secret(client_pk)
            t_encap = (time.perf_counter() - t0) / iterations

            # Measure Decapsulation
            t0 = time.perf_counter()
            for _ in range(iterations):
                shared_secret_c = client_kem.decap_secret(ciphertext)
            t_decap = (time.perf_counter() - t0) / iterations

            assert shared_secret_s == shared_secret_c

            print(f"[{kem_name}]")
            print(f"  Public Key Size : {len(client_pk):>5} bytes")
            print(f"  Ciphertext Size : {len(ciphertext):>5} bytes")
            print(f"  KeyGen Time     : {t_keygen * 1000:>7.3f} ms")
            print(f"  Encap Time      : {t_encap * 1000:>7.3f} ms")
            print(f"  Decap Time      : {t_decap * 1000:>7.3f} ms\n")

if __name__ == "__main__":
    # Test standard NIST ML-KEM levels
    for alg in ["Kyber512", "Kyber768", "Kyber1024"]:
        if alg in oqs.get_enabled_KEM_mechanisms():
            benchmark_kem_operations(alg)