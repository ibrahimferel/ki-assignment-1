"""Tests for app.crypto: ciphers, key wrapping and the engine.

Run only these tests with:
    pytest tests/test_crypto.py -v
"""

import secrets

import pytest

from app.crypto import (
    ALGORITHMS,
    CryptoError,
    EncryptedCopy,
    decrypt_copy,
    encrypt_all,
    encrypt_one,
)
from app.crypto import ciphers, keys

PLAINTEXTS = [b"", b"a", b"halo dunia", b"x" * 15, b"x" * 16, b"x" * 17, secrets.token_bytes(4096)]
PT_IDS = ["empty", "1B", "text", "15B", "16B", "17B", "4KB"]


@pytest.fixture()
def master_key():
    return secrets.token_bytes(keys.MASTER_KEY_LENGTH)


# ---------------------------------------------------------------- dependency

def test_pycryptodome_is_installed():
    """The code imports ``Crypto`` (pycryptodome), not ``cryptography``."""
    import Crypto  # noqa: F401


# ---------------------------------------------------------------- ciphers.py

@pytest.mark.parametrize("algorithm, length", [("AES", 32), ("DES", 8), ("RC4", 16)])
def test_key_len(algorithm, length):
    assert ciphers.key_len(algorithm) == length
    assert len(keys.generate_key(algorithm)) == length


def test_unknown_algorithm_is_rejected():
    with pytest.raises(CryptoError):
        ciphers.key_len("ROT13")


@pytest.mark.parametrize("algorithm", ["AES", "DES", "RC4"])
@pytest.mark.parametrize("plaintext", PLAINTEXTS, ids=PT_IDS)
def test_cipher_roundtrip(algorithm, plaintext):
    key = keys.generate_key(algorithm)
    result = ciphers.encrypt(algorithm, key, plaintext)
    assert result.ciphertext != plaintext or plaintext == b""
    back = ciphers.decrypt(algorithm, key, result.ciphertext, result.mode, result.iv)
    assert back == plaintext


@pytest.mark.parametrize("algorithm, block", [("AES", 16), ("DES", 8)])
def test_block_ciphers_use_cbc_with_random_iv(algorithm, block):
    key = keys.generate_key(algorithm)
    a = ciphers.encrypt(algorithm, key, b"same data")
    b = ciphers.encrypt(algorithm, key, b"same data")
    assert a.mode == "CBC"  # stored in the database as a string
    assert len(a.iv) == block
    assert a.iv != b.iv and a.ciphertext != b.ciphertext
    assert len(a.ciphertext) % block == 0


def test_rc4_has_no_mode_or_iv():
    result = ciphers.encrypt("RC4", keys.generate_key("RC4"), b"data")
    assert result.mode is None and result.iv is None


@pytest.mark.parametrize("algorithm", ["AES", "DES", "RC4"])
def test_wrong_key_length_is_rejected(algorithm):
    with pytest.raises(CryptoError):
        ciphers.encrypt(algorithm, b"short", b"data")


def test_wrong_key_does_not_give_plaintext():
    key, other = keys.generate_key("AES"), keys.generate_key("AES")
    r = ciphers.encrypt("AES", key, b"secret message!!")
    try:
        assert ciphers.decrypt("AES", other, r.ciphertext, r.mode, r.iv) != b"secret message!!"
    except CryptoError:
        pass  # bad padding is also an acceptable outcome


# ---------------------------------------------------------------- keys.py

def test_wrap_unwrap_roundtrip(master_key):
    secret = secrets.token_bytes(48)
    wrapped = keys.wrap_key(master_key, secret, "AES")
    assert secret not in wrapped
    assert keys.unwrap_key(master_key, wrapped, "AES") == secret


def test_unwrap_with_wrong_master_key_fails(master_key):
    wrapped = keys.wrap_key(master_key, b"k" * 48, "AES")
    with pytest.raises(CryptoError):
        keys.unwrap_key(secrets.token_bytes(32), wrapped, "AES")


def test_unwrap_with_wrong_algorithm_label_fails(master_key):
    wrapped = keys.wrap_key(master_key, b"k" * 48, "AES")
    with pytest.raises(CryptoError):
        keys.unwrap_key(master_key, wrapped, "DES")


def test_tampered_wrapped_key_fails(master_key):
    wrapped = bytearray(keys.wrap_key(master_key, b"k" * 48, "AES"))
    wrapped[-1] ^= 1
    with pytest.raises(CryptoError):
        keys.unwrap_key(master_key, bytes(wrapped), "AES")


@pytest.mark.parametrize("bad", [b"", b"x" * 31, "a" * 32, None])
def test_bad_master_key_is_rejected(bad):
    with pytest.raises(CryptoError):
        keys.wrap_key(bad, b"k" * 16, "AES")


# ---------------------------------------------------------------- engine.py

@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("plaintext", PLAINTEXTS, ids=PT_IDS)
def test_engine_roundtrip(master_key, algorithm, plaintext):
    copy = encrypt_one(algorithm, master_key, plaintext)
    assert isinstance(copy, EncryptedCopy)
    assert copy.algorithm == algorithm
    assert copy.encryption_time >= 0
    back = decrypt_copy(
        algorithm=copy.algorithm,
        mode=copy.mode,
        iv=copy.iv,
        wrapped_key=copy.wrapped_key,
        ciphertext=copy.ciphertext,
        master_key=master_key,
    )
    assert back == plaintext


def test_each_copy_uses_its_own_key(master_key):
    a = encrypt_one("AES", master_key, b"data")
    b = encrypt_one("AES", master_key, b"data")
    assert a.wrapped_key != b.wrapped_key
    assert master_key not in a.wrapped_key


def test_encrypt_all_returns_three_copies(master_key):
    copies = encrypt_all(b"halo", master_key)
    assert sorted(c.algorithm for c in copies) == ["AES", "DES", "RC4"]


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_tampered_ciphertext_is_detected(master_key, algorithm):
    copy = encrypt_one(algorithm, master_key, b"important data here")
    broken = bytearray(copy.ciphertext)
    broken[0] ^= 1
    with pytest.raises(CryptoError):
        decrypt_copy(
            algorithm=algorithm, mode=copy.mode, iv=copy.iv,
            wrapped_key=copy.wrapped_key, ciphertext=bytes(broken),
            master_key=master_key,
        )


def test_wrong_master_key_cannot_decrypt(master_key):
    copy = encrypt_one("AES", master_key, b"data")
    with pytest.raises(CryptoError):
        decrypt_copy(
            algorithm="AES", mode=copy.mode, iv=copy.iv,
            wrapped_key=copy.wrapped_key, ciphertext=copy.ciphertext,
            master_key=secrets.token_bytes(32),
        )


def test_engine_rejects_unknown_algorithm(master_key):
    with pytest.raises(CryptoError):
        encrypt_one("ROT13", master_key, b"data")
