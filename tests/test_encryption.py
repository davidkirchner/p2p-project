# test_encryption.py
import pytest
from unittest.mock import MagicMock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from nacl.exceptions import CryptoError

from kademlia.kademlia import kademlia_key
from encryption import PeerEncryption, UserEncryption, Signature, EncryptedMsg


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_user_encryption() -> UserEncryption:
    return UserEncryption.create()


def make_peer_encryption(user: UserEncryption) -> PeerEncryption:
    return PeerEncryption.from_peer(user.id, user.public_bytes)


# ---------------------------------------------------------------------------
# UserEncryption.create
# ---------------------------------------------------------------------------

class TestUserEncryptionCreate:
    def test_returns_user_encryption_instance(self):
        ue = make_user_encryption()
        assert isinstance(ue, UserEncryption)

    def test_has_valid_id(self):
        ue = make_user_encryption()
        assert ue.id == kademlia_key(ue.public_bytes)

    def test_public_bytes_length(self):
        ue = make_user_encryption()
        assert len(ue.public_bytes) == 32

    def test_private_bytes_length(self):
        ue = make_user_encryption()
        assert len(ue.private_bytes) == 32

    def test_two_instances_have_different_keys(self):
        ue1 = make_user_encryption()
        ue2 = make_user_encryption()
        assert ue1.public_bytes != ue2.public_bytes


# ---------------------------------------------------------------------------
# PeerEncryption.from_peer
# ---------------------------------------------------------------------------

class TestPeerEncryptionFromPeer:
    def test_creates_peer_encryption(self):
        ue = make_user_encryption()
        pe = make_peer_encryption(ue)
        assert isinstance(pe, PeerEncryption)

    def test_public_bytes_roundtrip(self):
        ue = make_user_encryption()
        pe = make_peer_encryption(ue)
        assert pe.public_bytes == ue.public_bytes

    def test_id_preserved(self):
        ue = make_user_encryption()
        pe = make_peer_encryption(ue)
        assert pe.id == ue.id


# ---------------------------------------------------------------------------
# Sign / Verify
# ---------------------------------------------------------------------------

class TestSignVerify:
    def test_valid_signature_does_not_raise(self):
        ue = make_user_encryption()
        message = b"hello world"
        sig = ue.sign(message)
        ue.verify(message, sig)  # must not raise

    def test_verify_via_peer_encryption(self):
        ue = make_user_encryption()
        pe = make_peer_encryption(ue)
        message = b"test message"
        sig = ue.sign(message)
        pe.verify(message, sig)  # must not raise

    def test_wrong_message_raises(self):
        ue = make_user_encryption()
        sig = ue.sign(b"correct")
        with pytest.raises(Exception):
            ue.verify(b"wrong", sig)

    def test_tampered_signature_raises(self):
        ue = make_user_encryption()
        sig = bytearray(ue.sign(b"data"))
        sig[0] ^= 0xFF
        with pytest.raises(Exception):
            ue.verify(b"data", Signature(bytes(sig)))

    def test_sign_returns_bytes(self):
        ue = make_user_encryption()
        sig = ue.sign(b"msg")
        assert isinstance(sig, bytes)


# ---------------------------------------------------------------------------
# Encrypt / Decrypt
# ---------------------------------------------------------------------------

class TestEncryptDecrypt:
    def test_encrypt_returns_bytes(self):
        sender = make_user_encryption()
        receiver = make_user_encryption()
        ct = sender.encrypt(receiver, b"secret")
        assert isinstance(ct, bytes)

    def test_decrypt_recovers_plaintext(self):
        sender = make_user_encryption()
        receiver = make_user_encryption()
        plaintext = b"secret message"
        ct = sender.encrypt(receiver, plaintext)
        assert receiver.decrypt(ct) == plaintext

    def test_wrong_receiver_cannot_decrypt(self):
        sender = make_user_encryption()
        receiver = make_user_encryption()
        other = make_user_encryption()
        ct = sender.encrypt(receiver, b"secret")
        with pytest.raises(CryptoError):
            other.decrypt(ct)

    def test_ciphertext_differs_from_plaintext(self):
        sender = make_user_encryption()
        receiver = make_user_encryption()
        plaintext = b"secret"
        ct = sender.encrypt(receiver, plaintext)
        assert ct != plaintext

    def test_same_plaintext_produces_different_ciphertexts(self):
        """SealedBox uses ephemeral keys — ciphertext must be non-deterministic."""
        sender = make_user_encryption()
        receiver = make_user_encryption()
        ct1 = sender.encrypt(receiver, b"same")
        ct2 = sender.encrypt(receiver, b"same")
        assert ct1 != ct2


# ---------------------------------------------------------------------------
# from_stored (async)
# ---------------------------------------------------------------------------

class TestFromStored:
    @pytest.mark.asyncio
    async def test_returns_user_encryption_when_private_key_present(self):
        ue = make_user_encryption()
        user = MagicMock()
        user.id = ue.id
        user.private_identity = ue.private_bytes
        user.public_identity = ue.public_bytes

        result = await PeerEncryption.from_stored(user)
        assert isinstance(result, UserEncryption)
        assert result.public_bytes == ue.public_bytes

    @pytest.mark.asyncio
    async def test_returns_peer_encryption_when_no_private_key(self):
        ue = make_user_encryption()
        user = MagicMock()
        user.id = ue.id
        user.private_identity = None
        user.public_identity = ue.public_bytes

        result = await PeerEncryption.from_stored(user)
        assert isinstance(result, PeerEncryption)
        assert not isinstance(result, UserEncryption)
        assert result.public_bytes == ue.public_bytes