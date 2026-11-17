"""Tests for the Assignment 2 sharing crypto (contract 1).

Covers the RSA-OAEP part of app/crypto/asymmetric.py and all of app/crypto/share.py.
Every key, password and file here is synthetic test data.
Each block is marked with the checkpoint (CP) whose code makes it pass.
"""
import ast
import base64
import inspect
import os
import pathlib
import unicodedata

import pytest
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import app.crypto as crypto
import app.crypto.asymmetric as asymmetric
import app.crypto.share as share
from app.crypto import (
    CryptoError,
    decode_key_package,
    decrypt_shared,
    decrypt_with_password,
    encode_key_package,
    encrypt_for_user,
    encrypt_shared,
    generate_user_keypair,
    new_share_key,
    oaep_label,
    share_aad,
    unwrap_share_key,
    wrap_share_key,
)
from app.crypto.keys import wrap_key

ROOT = pathlib.Path(__file__).resolve().parents[1]
PASSWORD = "synthetic password for share tests"
OTHER_PASSWORD = "another synthetic password"
MASTER_KEY = bytes(range(32))  # synthetic, never the real MASTER_KEY
OTHER_MASTER_KEY = bytes(range(1, 33))
SECRET_FILE = b"synthetic file contents " * 64

SYNTHETIC_RSA_CIPHERTEXT = bytes(i % 256 for i in range(384))
_B64 = base64.b64encode(SYNTHETIC_RSA_CIPHERTEXT).decode("ascii")
GOOD_PACKAGE = "\n".join(
    ["MEDVAULT-KEY-V1", "REQUEST 42"] + [_B64[i:i + 64] for i in range(0, len(_B64), 64)]
)


def failure_message(fn, *args):
    """Call fn, require a CryptoError with no chained exception, return its message."""
    with pytest.raises(CryptoError) as info:
        fn(*args)
    error = info.value
    assert error.__context__ is None
    assert error.__cause__ is None
    return error.message


def as_bytes(pem):
    return pem.encode("ascii") if isinstance(pem, str) else pem


def password_bytes(password):
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def oaep_padding(label):
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=label
    )


# ================================================================ CP1: contract

CONTRACT = {
    "generate_user_keypair": ("app.crypto.asymmetric", ["password"]),
    "encrypt_for_user": ("app.crypto.asymmetric", ["public_pem", "data", "label"]),
    "decrypt_with_password": (
        "app.crypto.asymmetric",
        ["encrypted_private_pem", "password", "ciphertext", "label"],
    ),
    "new_share_key": ("app.crypto.share", []),
    "encrypt_shared": ("app.crypto.share", ["key", "plaintext", "aad"]),
    "decrypt_shared": ("app.crypto.share", ["key", "nonce", "ciphertext", "aad"]),
    "wrap_share_key": ("app.crypto.share", ["master_key", "key", "request_id"]),
    "unwrap_share_key": ("app.crypto.share", ["master_key", "wrapped", "request_id"]),
    "encode_key_package": ("app.crypto.share", ["request_id", "encrypted_key"]),
    "decode_key_package": ("app.crypto.share", ["text"]),
}


@pytest.mark.parametrize("name", sorted(CONTRACT))
def test_contract_function_is_exported_with_the_agreed_signature(name):
    module_name, params = CONTRACT[name]
    function = getattr(crypto, name)
    assert function.__module__ == module_name
    signature = inspect.signature(function)
    assert list(signature.parameters) == params
    for parameter in signature.parameters.values():
        assert parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
        assert parameter.default is inspect.Parameter.empty


SHARE_HELPERS = {
    "share_aad": ["request_id", "file_id"],
    "oaep_label": ["request_id"],
}


@pytest.mark.parametrize("name", sorted(SHARE_HELPERS))
def test_share_helper_is_exported_with_the_agreed_signature(name):
    function = getattr(crypto, name)
    assert function.__module__ == "app.crypto.share"
    assert list(inspect.signature(function).parameters) == SHARE_HELPERS[name]


def test_module_public_names_are_exactly_the_agreed_ones():
    assert asymmetric.__all__ == [
        "generate_user_keypair",
        "encrypt_for_user",
        "decrypt_with_password",
    ]
    share_names = {name for name, (module, _) in CONTRACT.items() if module == "app.crypto.share"}
    assert sorted(share.__all__) == sorted(share_names | set(SHARE_HELPERS))


# ================================================================ CP2: encoding

BAD_IDS = [0, -1, 2**63, True, False, 1.0, "1", None, b"\x01"]


def test_share_aad_is_request_id_then_file_id_as_8_byte_big_endian():
    assert share_aad(1, 2) == bytes.fromhex("0000000000000001" "0000000000000002")
    assert share_aad(2**63 - 1, 258) == bytes.fromhex("7fffffffffffffff" "0000000000000102")
    assert share_aad(1, 2) != share_aad(2, 1)


def test_oaep_label_is_the_request_id_as_8_byte_big_endian():
    assert oaep_label(1) == bytes.fromhex("0000000000000001")
    assert oaep_label(0x0102030405060708) == bytes.fromhex("0102030405060708")
    assert oaep_label(2**63 - 1) == bytes.fromhex("7fffffffffffffff")


def test_share_aad_and_oaep_label_reject_bad_ids_with_one_message():
    messages = set()
    for bad in BAD_IDS:
        messages.add(failure_message(share_aad, bad, 1))
        messages.add(failure_message(share_aad, 1, bad))
        messages.add(failure_message(oaep_label, bad))
    assert len(messages) == 1


# ================================================================ CP3: RSA-OAEP


@pytest.fixture
def pair_a():
    return generate_user_keypair(PASSWORD)


@pytest.fixture
def pair_b(pair_a):
    # Built after pair_a, so the 3-key test pool gives it a different key.
    return generate_user_keypair(OTHER_PASSWORD)


def test_oaep_round_trip_returns_the_share_key(pair_a):
    public_pem, private_pem = pair_a
    share_key = bytes(range(32))
    ciphertext = encrypt_for_user(public_pem, share_key, oaep_label(42))
    assert isinstance(ciphertext, bytes)
    assert len(ciphertext) == 384
    assert decrypt_with_password(private_pem, PASSWORD, ciphertext, oaep_label(42)) == share_key


def test_oaep_encryption_is_randomised(pair_a):
    public_pem, _ = pair_a
    first = encrypt_for_user(public_pem, b"k" * 32, oaep_label(1))
    second = encrypt_for_user(public_pem, b"k" * 32, oaep_label(1))
    assert first != second


def test_oaep_accepts_318_bytes_and_rejects_319(pair_a):
    public_pem, private_pem = pair_a
    ciphertext = encrypt_for_user(public_pem, b"x" * 318, b"label")
    assert decrypt_with_password(private_pem, PASSWORD, ciphertext, b"label") == b"x" * 318
    failure_message(encrypt_for_user, public_pem, b"x" * 319, b"label")


def test_password_is_normalised_like_generate_user_keypair():
    # U+FB01 (the "fi" ligature) becomes "fi" under NFKC.
    public_pem, private_pem = generate_user_keypair("synthetic \ufb01le password")
    ciphertext = encrypt_for_user(public_pem, b"k" * 32, oaep_label(5))
    opened = decrypt_with_password(private_pem, "synthetic file password", ciphertext, oaep_label(5))
    assert opened == b"k" * 32


def test_password_of_exactly_1024_characters_is_accepted():
    # The limit is 1024 characters (handoff, section 3); 1025 is rejected further down.
    password = "p" * 1024
    public_pem, private_pem = generate_user_keypair(password)
    ciphertext = encrypt_for_user(public_pem, b"k" * 32, oaep_label(9))
    assert decrypt_with_password(private_pem, password, ciphertext, oaep_label(9)) == b"k" * 32


def test_every_decrypt_failure_has_the_same_message(pair_a, pair_b):
    public_a, private_a = pair_a
    _, private_b = pair_b
    label = oaep_label(42)
    good = encrypt_for_user(public_a, b"k" * 32, label)
    flipped = bytes([good[0] ^ 1]) + good[1:]
    cases = [
        (private_a, OTHER_PASSWORD, good, label),  # wrong password
        (private_a, PASSWORD, good, oaep_label(43)),  # label of another request
        (private_b, OTHER_PASSWORD, good, label),  # another user's private key
        (private_a, PASSWORD, flipped, label),  # tampered ciphertext
        (private_a, PASSWORD, good[:-1], label),  # truncated ciphertext
        (private_a, PASSWORD, b"", label),  # empty ciphertext
        (b"not a pem", PASSWORD, good, label),  # broken PEM
        (public_a, PASSWORD, good, label),  # public key instead of private key
        (private_a, "x" * 1025, good, label),  # password over 1024 characters
        (private_a, PASSWORD.encode("utf-8"), good, label),  # password not a str
        (private_a, PASSWORD, good, "label as str"),  # label not bytes
        (private_a, PASSWORD, good.hex(), label),  # ciphertext not bytes
    ]
    messages = {failure_message(decrypt_with_password, *case) for case in cases}
    assert len(messages) == 1


def test_every_encrypt_failure_has_the_same_message(pair_a):
    public_pem, private_pem = pair_a
    small_key = RSA.generate(1024)
    cases = [
        (public_pem, b"x" * 319, b"label"),  # too long for OAEP-SHA256 on 3072 bits
        (public_pem, "text", b"label"),  # data not bytes
        (public_pem, b"k" * 32, "label"),  # label not bytes
        (b"not a pem", b"k" * 32, b"label"),  # broken PEM
        (private_pem, b"k" * 32, b"label"),  # encrypted private key, not a public key
        (small_key.export_key(), b"k" * 32, b"label"),  # plain private key
        (small_key.publickey().export_key(), b"k" * 32, b"label"),  # not 3072 bits
    ]
    messages = {failure_message(encrypt_for_user, *case) for case in cases}
    assert len(messages) == 1


def test_cryptography_decrypts_what_encrypt_for_user_produces(pair_a):
    public_pem, private_pem = pair_a
    label = oaep_label(7)
    ciphertext = encrypt_for_user(public_pem, b"k" * 32, label)
    # Open the scrypt PEM with pycryptodome, then give cryptography a plain DER copy.
    opened = RSA.import_key(private_pem, passphrase=password_bytes(PASSWORD))
    private_key = serialization.load_der_private_key(
        opened.export_key(format="DER", pkcs=8), password=None
    )
    assert private_key.decrypt(ciphertext, oaep_padding(label)) == b"k" * 32


def test_decrypt_with_password_opens_what_cryptography_encrypts(pair_a):
    public_pem, private_pem = pair_a
    label = oaep_label(7)
    public_key = serialization.load_pem_public_key(as_bytes(public_pem))
    ciphertext = public_key.encrypt(b"k" * 32, oaep_padding(label))
    assert decrypt_with_password(private_pem, PASSWORD, ciphertext, label) == b"k" * 32


# ============================================== CP4: share key, AES-GCM, wrapping


def test_new_share_key_is_32_fresh_random_bytes():
    keys = {new_share_key() for _ in range(50)}
    assert len(keys) == 50
    assert all(isinstance(key, bytes) and len(key) == 32 for key in keys)


def test_shared_copy_round_trip():
    key = new_share_key()
    aad = share_aad(7, 9)
    nonce, ciphertext = encrypt_shared(key, SECRET_FILE, aad)
    assert isinstance(nonce, bytes) and len(nonce) == 12
    assert len(ciphertext) == len(SECRET_FILE) + 16
    assert decrypt_shared(key, nonce, ciphertext, aad) == SECRET_FILE


def test_empty_file_round_trip():
    key = new_share_key()
    nonce, ciphertext = encrypt_shared(key, b"", share_aad(1, 1))
    assert len(ciphertext) == 16
    assert decrypt_shared(key, nonce, ciphertext, share_aad(1, 1)) == b""


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 1024 * 1024])
def test_ciphertext_is_always_plaintext_plus_a_16_byte_tag(size):
    key = new_share_key()
    data = os.urandom(size)
    nonce, ciphertext = encrypt_shared(key, data, share_aad(3, 4))
    assert len(ciphertext) == size + 16
    assert decrypt_shared(key, nonce, ciphertext, share_aad(3, 4)) == data


def test_nonce_is_fresh_on_every_call():
    key = new_share_key()
    results = [encrypt_shared(key, b"same bytes", share_aad(1, 1)) for _ in range(200)]
    assert len({nonce for nonce, _ in results}) == 200
    assert len({ciphertext for _, ciphertext in results}) == 200


def test_every_decrypt_shared_failure_has_the_same_message():
    key = new_share_key()
    aad = share_aad(7, 9)
    nonce, ciphertext = encrypt_shared(key, SECRET_FILE, aad)
    cases = [
        (new_share_key(), nonce, ciphertext, aad),  # wrong key
        (key, nonce, ciphertext, share_aad(7, 10)),  # AAD of another file
        (key, nonce, ciphertext, share_aad(8, 9)),  # AAD of another request
        (key, bytes([nonce[0] ^ 1]) + nonce[1:], ciphertext, aad),  # wrong nonce
        (key, nonce, ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), aad),  # tag changed
        (key, nonce, bytes([ciphertext[0] ^ 1]) + ciphertext[1:], aad),  # body changed
        (key, nonce, ciphertext[:-1], aad),  # truncated
        (key, nonce, ciphertext[:15], aad),  # shorter than a tag
        (key, nonce[:11], ciphertext, aad),  # nonce of the wrong length
        (key[:31], nonce, ciphertext, aad),  # key of the wrong length
        (key.hex(), nonce, ciphertext, aad),  # key not bytes
        (key, nonce, ciphertext, "aad as str"),  # AAD not bytes
    ]
    messages = {failure_message(decrypt_shared, *case) for case in cases}
    assert len(messages) == 1


def test_encrypt_shared_rejects_bad_input_with_one_message():
    key = new_share_key()
    cases = [
        (key[:31], b"data", b"aad"),
        (key + b"\x00", b"data", b"aad"),
        (key.hex(), b"data", b"aad"),
        (key, "data", b"aad"),
        (key, b"data", "aad"),
    ]
    messages = {failure_message(encrypt_shared, *case) for case in cases}
    assert len(messages) == 1


def test_wrap_share_key_round_trip():
    key = new_share_key()
    wrapped = wrap_share_key(MASTER_KEY, key, 42)
    assert isinstance(wrapped, bytes)
    assert len(wrapped) == 65
    assert key not in wrapped
    assert unwrap_share_key(MASTER_KEY, wrapped, 42) == key


def test_wrap_share_key_accepts_the_largest_request_id():
    key = new_share_key()
    wrapped = wrap_share_key(MASTER_KEY, key, 2**63 - 1)
    assert unwrap_share_key(MASTER_KEY, wrapped, 2**63 - 1) == key


def test_every_unwrap_failure_has_the_same_message():
    key = new_share_key()
    wrapped = wrap_share_key(MASTER_KEY, key, 42)
    sixteen_byte_key = wrap_key(MASTER_KEY, b"k" * 16, "SHARE-42")
    cases = [
        (OTHER_MASTER_KEY, wrapped, 42),  # wrong master key
        (MASTER_KEY, wrapped, 43),  # another request id
        (MASTER_KEY, wrapped[:-1] + bytes([wrapped[-1] ^ 1]), 42),  # tampered
        (MASTER_KEY, bytes([2]) + wrapped[1:], 42),  # unknown version byte
        (MASTER_KEY, wrapped[:20], 42),  # too short
        (MASTER_KEY, b"", 42),
        (MASTER_KEY, wrapped.hex(), 42),  # not bytes
        (MASTER_KEY[:31], wrapped, 42),  # master key of the wrong size
        (MASTER_KEY, sixteen_byte_key, 42),  # unwraps, but is not 32 bytes
        (MASTER_KEY, wrapped, 0),
        (MASTER_KEY, wrapped, True),
        (MASTER_KEY, wrapped, "42"),
    ]
    messages = {failure_message(unwrap_share_key, *case) for case in cases}
    assert len(messages) == 1


def test_wrap_share_key_rejects_bad_input_with_one_message():
    key = new_share_key()
    cases = [
        (MASTER_KEY, key[:31], 42),
        (MASTER_KEY, key + b"\x00", 42),
        (MASTER_KEY, key.hex(), 42),
        (MASTER_KEY[:31], key, 42),
        (MASTER_KEY, key, 0),
        (MASTER_KEY, key, -5),
        (MASTER_KEY, key, 2**63),
        (MASTER_KEY, key, True),
        (MASTER_KEY, key, "42"),
    ]
    messages = {failure_message(wrap_share_key, *case) for case in cases}
    assert len(messages) == 1


# ============================================================= CP5: key package


def _bad_packages():
    header, request, *body = GOOD_PACKAGE.split("\n")
    b64 = "".join(body)

    def build(h=header, r=request, b=b64):
        return "\n".join([h, r, b])

    return {
        "empty": "",
        "header only": header,
        "no body": header + "\n" + request,
        "version 2": build(h="MEDVAULT-KEY-V2"),
        "lowercase header": build(h=header.lower()),
        "missing request line": header + "\n" + b64,
        "request zero": build(r="REQUEST 0"),
        "request negative": build(r="REQUEST -1"),
        "request leading zero": build(r="REQUEST 042"),
        "request too large": build(r="REQUEST %d" % 2**63),
        "request split": build(r="REQUEST 4 2"),
        "request non-ascii digits": build(r="REQUEST \u0664\u0662"),
        "request word": build(r="REQUEST forty-two"),
        "bad base64 character": build(b="*" + b64[1:]),
        "base64 too short": build(b=b64[:-4]),
        "base64 too long": build(b=b64 + "AAAA"),
        "padding in the middle": build(b=b64[:100] + "=" + b64[101:]),
        "trailing chat text": GOOD_PACKAGE + "\nthanks!",
        "over 2 KB": GOOD_PACKAGE + " " * 2048,
        "bytes": GOOD_PACKAGE.encode("ascii"),
        "None": None,
        "int": 42,
    }


BAD_PACKAGES = _bad_packages()


def test_key_package_round_trip():
    for request_id in (1, 42, 2**63 - 1):
        text = encode_key_package(request_id, SYNTHETIC_RSA_CIPHERTEXT)
        assert isinstance(text, str)
        assert decode_key_package(text) == (request_id, SYNTHETIC_RSA_CIPHERTEXT)


def test_key_package_layout_is_locked():
    assert encode_key_package(42, SYNTHETIC_RSA_CIPHERTEXT) == GOOD_PACKAGE
    assert len(GOOD_PACKAGE) <= 2048


def test_key_package_survives_copy_and_paste_whitespace():
    header, request, *body = GOOD_PACKAGE.split("\n")
    variants = [
        GOOD_PACKAGE.replace("\n", "\r\n"),
        "\n\n  " + GOOD_PACKAGE + "  \n\n",
        "\n".join([header, "", request, ""] + body),
        "\n".join([header, request, "".join(body)]),
        "\n".join([" " + header + "\t", request, " ".join(body[:4]), "\t".join(body[4:])]),
    ]
    for variant in variants:
        assert decode_key_package(variant) == (42, SYNTHETIC_RSA_CIPHERTEXT)


@pytest.mark.parametrize("name", sorted(BAD_PACKAGES))
def test_decode_rejects_malformed_package(name):
    failure_message(decode_key_package, BAD_PACKAGES[name])


def test_all_malformed_packages_share_one_message():
    messages = {failure_message(decode_key_package, text) for text in BAD_PACKAGES.values()}
    assert len(messages) == 1


def test_encode_key_package_rejects_bad_input_with_one_message():
    cases = [
        (0, SYNTHETIC_RSA_CIPHERTEXT),
        (True, SYNTHETIC_RSA_CIPHERTEXT),
        ("42", SYNTHETIC_RSA_CIPHERTEXT),
        (2**63, SYNTHETIC_RSA_CIPHERTEXT),
        (42, SYNTHETIC_RSA_CIPHERTEXT[:-1]),
        (42, SYNTHETIC_RSA_CIPHERTEXT + b"\x00"),
        (42, SYNTHETIC_RSA_CIPHERTEXT.hex()),
    ]
    messages = {failure_message(encode_key_package, *case) for case in cases}
    assert len(messages) == 1


# ===================================================== CP6: end to end, hygiene


def test_full_sharing_flow_with_real_key_pairs(pair_a):
    """B makes K, stores it wrapped and sends A the package; A unlocks and reads."""
    public_a, private_a = pair_a
    request_id, file_id = 42, 7
    share_key = new_share_key()
    stored = wrap_share_key(MASTER_KEY, share_key, request_id)
    nonce, copy = encrypt_shared(share_key, SECRET_FILE, share_aad(request_id, file_id))
    package = encode_key_package(
        request_id, encrypt_for_user(public_a, share_key, oaep_label(request_id))
    )

    got_id, encrypted_key = decode_key_package(package)
    unlocked = decrypt_with_password(private_a, PASSWORD, encrypted_key, oaep_label(got_id))
    assert got_id == request_id
    assert unlocked == unwrap_share_key(MASTER_KEY, stored, request_id)
    assert decrypt_shared(unlocked, nonce, copy, share_aad(request_id, file_id)) == SECRET_FILE


def test_a_package_for_one_request_cannot_unlock_another(pair_a):
    public_a, private_a = pair_a
    encrypted_key = encrypt_for_user(public_a, new_share_key(), oaep_label(42))
    forged = encode_key_package(43, encrypted_key)  # request line edited from 42 to 43
    got_id, payload = decode_key_package(forged)
    failure_message(decrypt_with_password, private_a, PASSWORD, payload, oaep_label(got_id))


def test_error_messages_never_contain_secret_material(pair_a):
    public_a, private_a = pair_a
    share_key = new_share_key()
    wrapped = wrap_share_key(MASTER_KEY, share_key, 42)
    nonce, copy = encrypt_shared(share_key, SECRET_FILE, share_aad(42, 7))
    package_key = encrypt_for_user(public_a, share_key, oaep_label(42))
    failing_calls = [
        (decrypt_with_password, (private_a, PASSWORD + "!", package_key, oaep_label(42))),
        (encrypt_for_user, (public_a, share_key * 10, oaep_label(42))),
        (decrypt_shared, (share_key, nonce, copy, share_aad(42, 8))),
        (encrypt_shared, (share_key, SECRET_FILE.decode("ascii"), share_aad(42, 7))),
        (unwrap_share_key, (OTHER_MASTER_KEY, wrapped, 42)),
        (wrap_share_key, (MASTER_KEY, share_key[:31], 42)),
        (decode_key_package, (GOOD_PACKAGE.replace("REQUEST 42", "REQUEST " + PASSWORD),)),
    ]
    secret_texts = [
        PASSWORD,
        "synthetic file contents",
        share_key.hex(),
        repr(share_key),
        MASTER_KEY.hex(),
        repr(MASTER_KEY),
    ]
    for function, args in failing_calls:
        with pytest.raises(CryptoError) as info:
            function(*args)
        error = info.value
        assert error.__context__ is None and error.__cause__ is None
        shown = " ".join([str(error), repr(error), error.message] + [str(a) for a in error.args])
        for secret in secret_texts:
            assert secret not in shown


NEW_MODULES = [ROOT / "app" / "crypto" / "asymmetric.py", ROOT / "app" / "crypto" / "share.py"]


def imported_modules(path):
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module)
    return names


@pytest.mark.parametrize("path", NEW_MODULES, ids=lambda path: path.name)
def test_production_crypto_never_imports_cryptography(path):
    assert not any(name.split(".")[0] == "cryptography" for name in imported_modules(path))


def test_share_module_imports_only_what_it_needs():
    assert imported_modules(ROOT / "app" / "crypto" / "share.py") == {
        "base64",
        "re",
        "secrets",
        "string",
        "struct",
        "typing",
        "Crypto.Cipher",
        "app.crypto.asymmetric",
        "app.crypto.errors",
        "app.crypto.keys",
    }


def test_share_module_never_logs_prints_or_asserts():
    path = ROOT / "app" / "crypto" / "share.py"
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        assert not isinstance(node, ast.Assert)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"print", "breakpoint"}
    assert not any(name.split(".")[0] == "logging" for name in imported_modules(path))
