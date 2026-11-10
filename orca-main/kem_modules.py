from abc import ABC, abstractmethod
from typing import Tuple
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class BaseKEM(ABC):
    """Unified interface for Classical, PQC, and Hybrid KEMs."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def generate_keypair(self) -> bytes:
        """Generates internal private state and returns serialized public key bytes."""
        pass

    @abstractmethod
    def encap_secret(self, peer_public_key: bytes) -> Tuple[bytes, bytes]:
        """Accepts peer public key, returns (ciphertext_bytes, shared_secret_bytes)."""
        pass

    @abstractmethod
    def decap_secret(self, ciphertext: bytes) -> bytes:
        """Accepts ciphertext bytes, returns shared_secret_bytes."""
        pass


# ============================================================================
# DELIVERABLE B: STANDALONE CLASSICAL MODULES (X25519 & NIST P-256)
# ============================================================================

class ClassicalX25519KEM(BaseKEM):
    """Ephemeral X25519 Diffie-Hellman wrapped as a KEM (32-byte raw keys)."""

    def __init__(self):
        self._private_key = None

    @property
    def name(self) -> str:
        return "Classical-X25519"

    def generate_keypair(self) -> bytes:
        self._private_key = x25519.X25519PrivateKey.generate()
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def encap_secret(self, peer_public_key: bytes) -> Tuple[bytes, bytes]:
        ephemeral_priv = x25519.X25519PrivateKey.generate()
        ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
        raw_shared = ephemeral_priv.exchange(peer_pub)

        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"tls13-classical-x25519"
        ).derive(raw_shared)

        return ephemeral_pub_bytes, shared_secret

    def decap_secret(self, ciphertext: bytes) -> bytes:
        peer_ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(ciphertext)
        raw_shared = self._private_key.exchange(peer_ephemeral_pub)

        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"tls13-classical-x25519"
        ).derive(raw_shared)


class ClassicalP256KEM(BaseKEM):
    """Ephemeral secp256r1 (NIST P-256) ECDH wrapped as a KEM (65-byte uncompressed keys)."""

    def __init__(self):
        self._private_key = None

    @property
    def name(self) -> str:
        return "Classical-secp256r1"

    def generate_keypair(self) -> bytes:
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

    def encap_secret(self, peer_public_key: bytes) -> Tuple[bytes, bytes]:
        ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
        ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public_key)
        raw_shared = ephemeral_priv.exchange(ec.ECDH(), peer_pub)

        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"tls13-classical-p256"
        ).derive(raw_shared)

        return ephemeral_pub_bytes, shared_secret

    def decap_secret(self, ciphertext: bytes) -> bytes:
        peer_ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ciphertext)
        raw_shared = self._private_key.exchange(ec.ECDH(), peer_ephemeral_pub)

        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"tls13-classical-p256"
        ).derive(raw_shared)


# ============================================================================
# DELIVERABLE C: STANDALONE PQC MODULE (ML-KEM / CRYSTALS-Kyber)
# ============================================================================

class PQCKEM(BaseKEM):
    """Post-Quantum KEM wrapper around liboqs (supports ML-KEM-512/768/1024)."""

    def __init__(self, alg_name: str = "ML-KEM-768"):
        enabled = oqs.get_enabled_kem_mechanisms()
        # Fallback if older liboqs uses "Kyber768" naming instead of "ML-KEM-768"
        if alg_name not in enabled:
            fallback_map = {
                "ML-KEM-512": "Kyber512",
                "ML-KEM-768": "Kyber768",
                "ML-KEM-1024": "Kyber1024"
            }
            alg_name = fallback_map.get(alg_name, alg_name)
        self.alg_name = alg_name
        self._kem = oqs.KeyEncapsulation(self.alg_name)

    @property
    def name(self) -> str:
        return f"PQC-{self.alg_name}"

    def generate_keypair(self) -> bytes:
        return self._kem.generate_keypair()

    def encap_secret(self, peer_public_key: bytes) -> Tuple[bytes, bytes]:
        ciphertext, shared_secret = self._kem.encap_secret(peer_public_key)
        return ciphertext, shared_secret

    def decap_secret(self, ciphertext: bytes) -> bytes:
        return self._kem.decap_secret(ciphertext)

    def __del__(self):
        if hasattr(self, "_kem") and self._kem is not None:
            self._kem.free()


# ============================================================================
# DELIVERABLE D: HYBRID KEM MODULE (X25519 + ML-KEM-768)
# ============================================================================

class HybridX25519MLKEM(BaseKEM):
    """
    IETF Draft-compliant Hybrid KEM combining X25519 (32B) and ML-KEM (768/512/1024).
    - Public Key: pk_x25519 (32B) || pk_pqc
    - Ciphertext: ct_x25519 (32B) || ct_pqc
    - Shared Secret: HKDF-SHA256(ss_x25519 || ss_pqc)
    """
    X25519_KEY_SIZE = 32

    def __init__(self, pqc_alg: str = "ML-KEM-768"):
        self._x25519_priv = None
        self._pqc = PQCKEM(pqc_alg)
        self._pqc_alg = self._pqc.alg_name

    @property
    def name(self) -> str:
        return f"Hybrid-X25519+{self._pqc_alg}"

    def generate_keypair(self) -> bytes:
        # 1. Classical X25519 KeyGen
        self._x25519_priv = x25519.X25519PrivateKey.generate()
        pk_c = self._x25519_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        # 2. PQC ML-KEM KeyGen
        pk_pq = self._pqc.generate_keypair()

        # Concatenate keys: 32 bytes X25519 + N bytes ML-KEM
        return pk_c + pk_pq

    def encap_secret(self, peer_public_key: bytes) -> Tuple[bytes, bytes]:
        # Split composite public key
        peer_pk_c = peer_public_key[:self.X25519_KEY_SIZE]
        peer_pk_pq = peer_public_key[self.X25519_KEY_SIZE:]

        # 1. Classical X25519 Exchange
        ephemeral_priv = x25519.X25519PrivateKey.generate()
        ct_c = ephemeral_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        ss_c = ephemeral_priv.exchange(x25519.X25519PublicKey.from_public_bytes(peer_pk_c))

        # 2. PQC ML-KEM Encapsulation
        ct_pq, ss_pq = self._pqc.encap_secret(peer_pk_pq)

        # 3. Combine secrets via HKDF-SHA256
        combined_ss = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"HybridKEM-X25519-MLKEM"
        ).derive(ss_c + ss_pq)

        return (ct_c + ct_pq), combined_ss

    def decap_secret(self, ciphertext: bytes) -> bytes:
        # Split composite ciphertext
        ct_c = ciphertext[:self.X25519_KEY_SIZE]
        ct_pq = ciphertext[self.X25519_KEY_SIZE:]

        # 1. Classical X25519 Exchange
        peer_ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(ct_c)
        ss_c = self._x25519_priv.exchange(peer_ephemeral_pub)

        # 2. PQC ML-KEM Decapsulation
        ss_pq = self._pqc.decap_secret(ct_pq)

        # 3. Combine secrets via HKDF-SHA256
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"HybridKEM-X25519-MLKEM"
        ).derive(ss_c + ss_pq)
