"""Tests for ``generate_user_keypair`` (app/crypto/asymmetric.py).

These tests use the REAL key generation on purpose (``real_keygen``). Only
three real RSA-3072 keys are made for the whole module, by the module
fixtures; every other test reuses them or never reaches the generator.
"""

import ast
import base64
import inspect
import re
import traceback
import unicodedata

import pytest
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerObjectId, DerOctetString, DerSequence
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from app.auth import services
from app.crypto import CryptoError, asymmetric
from app.crypto.asymmetric import generate_user_keypair

pytestmark = pytest.mark.usefixtures("real_keygen")

PASSWORD = "correct horse battery"
# Typed in a form NFKC changes: a full width letter, combining marks and a
# circled digit. Its NFKC form is "Pässwörd-密碼-1" with precomposed letters.
UNICODE_PASSWORD = "Ｐässwörd-密碼-①"
UNICODE_NORMALIZED = "Pässwörd-密碼-1"

BAD_PASSWORD_MESSAGE = (
    "Password must be a non-empty string of at most 1024 characters"
)
FAILED_MESSAGE = "Could not generate the user key pair"

PLAIN_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"Proc-Type",
)


# --------------------------------------------------------------- fixtures


@pytest.fixture(scope="module")
def pair():
    return generate_user_keypair(PASSWORD)


@pytest.fixture(scope="module")
def pair_again():
    return generate_user_keypair(PASSWORD)


@pytest.fixture(scope="module")
def unicode_pair():
    return generate_user_keypair(UNICODE_PASSWORD)


def kdf_details(private_pem):
    body = re.sub(rb"-----[A-Z ]+-----|\s", b"", private_pem)
    top = DerSequence().decode(base64.b64decode(body))
    algorithm = DerSequence().decode(top[0])
    pbes2 = DerSequence().decode(algorithm[1])
    kdf = DerSequence().decode(pbes2[0])
    scheme = DerSequence().decode(pbes2[1])
    params = DerSequence().decode(kdf[1])
    return {
        "pbes": DerObjectId().decode(algorithm[0]).value,
        "kdf": DerObjectId().decode(kdf[0]).value,
        "salt": DerOctetString().decode(params[0]).payload,
        "n": params[1],
        "r": params[2],
        "p": params[3],
        "cipher": DerObjectId().decode(scheme[0]).value,
    }


def open_private(private_pem, password_bytes):
    return serialization.load_pem_private_key(private_pem, password_bytes)


class FakeKey:
    """Stands in for an RSA key object; it is not a real key."""

    def __init__(self, private=None, public_error=None, private_error=None):
        self.private = private
        self.public_error = public_error
        self.private_error = private_error

    def publickey(self):
        return self

    def export_key(self, **options):
        if "passphrase" in options:
            if self.private_error is not None:
                raise self.private_error
            return self.private
        if self.public_error is not None:
            raise self.public_error
        return b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"


def trace_text(error):
    return "".join(
        traceback.format_exception(type(error), error, error.__traceback__)
    )


# ------------------------------------------------------ the module itself


def test_the_module_exports_only_the_one_function():
    assert asymmetric.__all__ == ["generate_user_keypair","encrypt_for_user","decrypt_with_password"]
    public = [
        name
        for name, value in vars(asymmetric).items()
        if not name.startswith("_")
        and inspect.isfunction(value)
        and value.__module__ == asymmetric.__name__
    ]
    assert public == ["generate_user_keypair","encrypt_for_user","decrypt_with_password"]


def test_none_of_the_other_contract_functions_exist_here():
    others = (
        "new_share_key",
        "encrypt_shared",
        "decrypt_shared",
        "wrap_share_key",
        "unwrap_share_key",
        "encode_key_package",
        "decode_key_package",
    )
    assert [name for name in others if hasattr(asymmetric, name)] == []


def test_source_never_logs_prints_or_asserts():
    tree = ast.parse(inspect.getsource(asymmetric))
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "print" not in called
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Assert)]
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module)
    assert imported == {"unicodedata", "Crypto.PublicKey","Crypto.Cipher", "Crypto.Hash", "app.crypto.errors"}


def test_the_key_size_and_exponent_are_pinned():
    assert asymmetric.RSA_BITS == 3072
    assert asymmetric.RSA_EXPONENT == 65537


# ------------------------------------------------------------ the output


def test_it_returns_two_byte_strings(pair):
    public_pem, private_pem = pair
    assert isinstance(pair, tuple) and len(pair) == 2
    assert type(public_pem) is bytes
    assert type(private_pem) is bytes


def test_the_public_key_is_a_3072_bit_spki_pem_with_exponent_65537(pair):
    public_pem = pair[0]
    assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----\n")
    assert public_pem.rstrip().endswith(b"-----END PUBLIC KEY-----")
    key = serialization.load_pem_public_key(public_pem)
    assert key.key_size == 3072
    assert key.public_numbers().e == 65537


def test_the_private_key_is_an_encrypted_pkcs8_pem(pair):
    private_pem = pair[1]
    assert private_pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
    footer = b"-----END ENCRYPTED PRIVATE KEY-----"
    assert private_pem.rstrip().endswith(footer)
    for marker in PLAIN_MARKERS:
        assert marker not in private_pem


def test_the_private_key_needs_a_password(pair):
    with pytest.raises(TypeError):
        serialization.load_pem_private_key(pair[1], None)


def test_the_private_key_does_not_contain_the_secret_numbers(pair):
    private = RSA.import_key(pair[1], passphrase=PASSWORD.encode("utf-8"))
    body = base64.b64decode(re.sub(rb"-----[A-Z ]+-----|\s", b"", pair[1]))
    size = 3072 // 16
    assert int(private.p).to_bytes(size, "big") not in body
    assert int(private.q).to_bytes(size, "big") not in body
    assert PASSWORD.encode("utf-8") not in pair[0] + pair[1] + body


# ------------------------------------------------- opening with a password


def test_cryptography_opens_it_with_the_password(pair):
    private = open_private(pair[1], PASSWORD.encode("utf-8"))
    public = serialization.load_pem_public_key(pair[0])
    assert private.key_size == 3072
    assert private.public_key().public_numbers() == public.public_numbers()


def test_pycryptodome_opens_it_with_the_password(pair):
    private = RSA.import_key(pair[1], passphrase=PASSWORD.encode("utf-8"))
    public = RSA.import_key(pair[0])
    assert private.size_in_bits() == 3072
    assert (private.n, private.e) == (public.n, public.e)


def test_a_wrong_password_opens_nothing(pair):
    wrong = b"correct horse batterz"
    with pytest.raises(ValueError):
        open_private(pair[1], wrong)
    with pytest.raises(ValueError):
        RSA.import_key(pair[1], passphrase=wrong)


def test_the_pair_works_for_rsa_oaep(pair):
    public = serialization.load_pem_public_key(pair[0])
    private = open_private(pair[1], PASSWORD.encode("utf-8"))
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=b"request-1",
    )
    message = b"x" * 32
    assert private.decrypt(public.encrypt(message, oaep), oaep) == message


# ------------------------------------------------------ the KDF parameters


def test_the_protection_is_scrypt_16384_8_1_with_aes_256_cbc(pair):
    details = kdf_details(pair[1])
    assert details["pbes"] == "1.2.840.113549.1.5.13"  # PBES2
    assert details["kdf"] == "1.3.6.1.4.1.11591.4.11"  # scrypt
    assert (details["n"], details["r"], details["p"]) == (2**14, 8, 1)
    assert details["cipher"] == "2.16.840.1.101.3.4.1.42"  # AES-256-CBC
    assert len(details["salt"]) == 16


def test_two_calls_give_different_keys_and_salts(pair, pair_again):
    assert pair[0] != pair_again[0]
    assert pair[1] != pair_again[1]
    assert kdf_details(pair[1])["salt"] != kdf_details(pair_again[1])["salt"]


# ------------------------------------------------- the password (NFKC, UTF-8)


def test_a_non_ascii_password_works(unicode_pair):
    key = open_private(unicode_pair[1], UNICODE_NORMALIZED.encode("utf-8"))
    assert key.key_size == 3072


def test_the_password_is_normalized_with_nfkc(unicode_pair):
    assert UNICODE_PASSWORD != UNICODE_NORMALIZED
    # Typed in any equivalent form, the same password opens the key.
    for typed in (UNICODE_PASSWORD, UNICODE_NORMALIZED):
        form = unicodedata.normalize("NFKC", typed)
        assert open_private(unicode_pair[1], form.encode("utf-8"))
    # The raw, unnormalized text does not.
    with pytest.raises(ValueError):
        open_private(unicode_pair[1], UNICODE_PASSWORD.encode("utf-8"))


def test_it_uses_the_same_form_as_the_login_check(unicode_pair):
    # authenticate() hashes this exact normalized text.
    form = services._check_password_shape(UNICODE_PASSWORD)
    assert form == UNICODE_NORMALIZED
    assert open_private(unicode_pair[1], form.encode("utf-8"))


# ------------------------------------------------------------- bad input


@pytest.mark.parametrize(
    "bad",
    [
        None,
        123,
        b"correct horse battery",
        bytearray(b"correct horse battery"),
        ["correct horse battery"],
        "",
        "x" * 1025,
        "\ud800",
        "pass\ud800word",
    ],
)
def test_an_unusable_password_is_refused_with_a_fixed_message(
    bad, monkeypatch
):
    calls = []
    monkeypatch.setattr(
        asymmetric, "_generate_rsa_key", lambda: calls.append(1)
    )
    with pytest.raises(CryptoError) as caught:
        generate_user_keypair(bad)
    error = caught.value
    assert error.message == str(error) == BAD_PASSWORD_MESSAGE
    assert error.__context__ is None and error.__cause__ is None
    assert calls == []  # no key was generated for a bad password


def test_the_longest_allowed_password_is_accepted(monkeypatch):
    fake = FakeKey(
        private=b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n"
        b"-----END ENCRYPTED PRIVATE KEY-----\n"
    )
    monkeypatch.setattr(asymmetric, "_generate_rsa_key", lambda: fake)
    assert generate_user_keypair("x" * 1024)[0].startswith(b"-----BEGIN")


# ------------------------------------------------------------- failures


@pytest.mark.parametrize(
    "fake",
    [
        FakeKey(private_error=RuntimeError("SECRET-DETAIL private bits")),
        FakeKey(public_error=RuntimeError("SECRET-DETAIL public bits")),
    ],
)
def test_an_internal_failure_becomes_a_fixed_crypto_error(fake, monkeypatch):
    monkeypatch.setattr(asymmetric, "_generate_rsa_key", lambda: fake)
    with pytest.raises(CryptoError) as caught:
        generate_user_keypair(PASSWORD)
    error = caught.value
    assert error.message == str(error) == FAILED_MESSAGE
    assert error.__context__ is None and error.__cause__ is None
    assert "SECRET-DETAIL" not in trace_text(error)
    assert PASSWORD not in trace_text(error)


def test_a_failing_generator_becomes_a_fixed_crypto_error(monkeypatch):
    def broken():
        raise MemoryError("SECRET-DETAIL")

    monkeypatch.setattr(asymmetric, "_generate_rsa_key", broken)
    with pytest.raises(CryptoError) as caught:
        generate_user_keypair(PASSWORD)
    assert caught.value.message == FAILED_MESSAGE
    assert caught.value.__context__ is None
    assert "SECRET-DETAIL" not in trace_text(caught.value)


def test_an_unencrypted_private_key_is_never_returned(monkeypatch):
    plain = FakeKey(
        private=b"-----BEGIN PRIVATE KEY-----\nAAAA\n"
        b"-----END PRIVATE KEY-----\n"
    )
    monkeypatch.setattr(asymmetric, "_generate_rsa_key", lambda: plain)
    with pytest.raises(CryptoError) as caught:
        generate_user_keypair(PASSWORD)
    assert caught.value.message == FAILED_MESSAGE
    assert caught.value.__context__ is None


def test_it_does_not_catch_keyboard_interrupt(monkeypatch):
    def interrupted():
        raise KeyboardInterrupt

    monkeypatch.setattr(asymmetric, "_generate_rsa_key", interrupted)
    with pytest.raises(KeyboardInterrupt):
        generate_user_keypair(PASSWORD)


def test_nothing_is_printed_or_logged(capsys, caplog, monkeypatch):
    broken = FakeKey(private_error=RuntimeError("SECRET-DETAIL"))
    monkeypatch.setattr(asymmetric, "_generate_rsa_key", lambda: broken)
    with pytest.raises(CryptoError):
        generate_user_keypair(PASSWORD)
    shown = capsys.readouterr()
    assert shown.out == "" and shown.err == ""
    assert caplog.text == ""
