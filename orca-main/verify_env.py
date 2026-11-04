import ssl
import sys
import cryptography
import oqs

def verify_environment():
    print("=" * 60)
    print("PHASE 1: ENVIRONMENT & LINKAGE VERIFICATION")
    print("=" * 60)
    
    print(f"Python Version       : {sys.version.split()[0]}")
    print(f"OpenSSL Version      : {ssl.OPENSSL_VERSION}")
    print(f"PyCA Cryptography    : {cryptography.__version__}")
    print(f"liboqs C Version     : {oqs.oqs_version()}")
    print(f"liboqs-python Version: {oqs.oqs_python_version()}")
    
    enabled_kems = oqs.get_enabled_kem_mechanisms()
    target_kems = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "Kyber512", "Kyber768", "Kyber1024"]
    available = [k for k in target_kems if k in enabled_kems]
    
    print(f"Total Enabled KEMs   : {len(enabled_kems)}")
    print(f"Target KEMs Found    : {', '.join(available)}")
    
    if not available:
        print("[-] ERROR: Neither ML-KEM nor Kyber mechanisms found in liboqs build!")
        sys.exit(1)
        
    print("[+] Environment verified and ready for Phase 1 benchmarking.")
    print("=" * 60)

if __name__ == "__main__":
    verify_environment()
