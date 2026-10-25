"""Tests for ``app.auth.services`` (policy, hashing, registration, login).

Most tests use a cheap Argon2 setting so the whole file stays fast. Tests
that care about the real parameters ask for the ``real_hasher`` fixture.
"""

import ast
import inspect
import types
import unicodedata

import pytest
from argon2 import PasswordHasher, extract_parameters
from sqlalchemy.exc import IntegrityError

from app.auth import services
from app.auth.services import (
    PASSWORD_MAX,
    PASSWORD_MIN,
    USERNAME_MAX,
    USERNAME_MIN,
    AuthError,
    PasswordPolicyError,
    UsernamePolicyError,
    UsernameTakenError,
    authenticate,
    get_user,
    hash_password,
    normalize_username,
    register_user,
    validate_password,
    verify_password,
)
from app.extensions import db
from app.models import User

pytestmark = pytest.mark.usefixtures("app")

GOOD = "correct horse battery"  # 21 characters, not on the common list


class SpyHasher:
    """Wraps a real hasher and records what it was asked to do."""

    def __init__(self, inner):
        self.inner = inner
        self.hash_calls = []
        self.verify_calls = []

    def hash(self, password):
        self.hash_calls.append(password)
        return self.inner.hash(password)

    def verify(self, stored_hash, password):
        self.verify_calls.append((stored_hash, password))
        return self.inner.verify(stored_hash, password)

    def reset(self):
        self.hash_calls.clear()
        self.verify_calls.clear()


@pytest.fixture(autouse=True)
def hasher(monkeypatch):
    """Cheap Argon2 for speed, plus a fresh dummy hash for every test."""
    spy = SpyHasher(PasswordHasher(time_cost=1, memory_cost=8, parallelism=1))
    monkeypatch.setattr(services, "_HASHER", spy)
    monkeypatch.setattr(services, "_dummy", None)
    return spy


@pytest.fixture()
def real_hasher(monkeypatch, hasher):
    """The library defaults that production uses."""
    spy = SpyHasher(PasswordHasher())
    monkeypatch.setattr(services, "_HASHER", spy)
    return spy


@pytest.fixture()
def alice(hasher):
    user = register_user("alice", GOOD)
    hasher.reset()
    return user


def code_of(exc_info):
    return exc_info.value.code


# --------------------------------------------------------------------------
# constants and hygiene
# --------------------------------------------------------------------------


def test_constants():
    assert (USERNAME_MIN, USERNAME_MAX) == (3, 32)
    assert (PASSWORD_MIN, PASSWORD_MAX) == (10, 128)


def test_username_max_matches_the_column():
    assert User.__table__.c.username.type.length == USERNAME_MAX


def test_public_names_are_exported():
    expected = {
        "AuthError",
        "PASSWORD_MAX",
        "PASSWORD_MIN",
        "PasswordPolicyError",
        "USERNAME_MAX",
        "USERNAME_MIN",
        "UsernamePolicyError",
        "UsernameTakenError",
        "authenticate",
        "get_user",
        "hash_password",
        "normalize_username",
        "register_user",
        "validate_password",
        "verify_password",
    }
    assert set(services.__all__) == expected
    for name in expected:
        assert hasattr(services, name)


def test_common_password_list_is_sane():
    common = services._COMMON_PASSWORDS
    assert 15 <= len(common) <= 30
    for entry in common:
        assert entry == entry.casefold()
        assert len(entry) >= PASSWORD_MIN, entry


def test_common_password_list_is_pinned():
    # A deliberate snapshot: changing the list must be a conscious edit.
    assert services._COMMON_PASSWORDS == {
        "password123",
        "password1234",
        "passw0rd123",
        "passwordpassword",
        "1234567890",
        "12345678910",
        "123456789012",
        "0123456789",
        "9876543210",
        "1111111111",
        "0000000000",
        "qwertyuiop",
        "qwerty12345",
        "qwerty123456",
        "1q2w3e4r5t",
        "asdfghjkl123",
        "abcdefghij",
        "abc1234567",
        "iloveyou123",
        "letmein1234",
        "welcome1234",
        "administrator",
        "changeme123",
    }


def test_source_never_logs_prints_or_uses_assert():
    tree = ast.parse(inspect.getsource(services))
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
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module.split(".")[0])
    assert not imported & {"logging", "flask", "flask_login", "werkzeug"}


# --------------------------------------------------------------------------
# exceptions
# --------------------------------------------------------------------------


def test_exception_hierarchy():
    assert issubclass(AuthError, Exception)
    for cls in (UsernamePolicyError, PasswordPolicyError, UsernameTakenError):
        assert issubclass(cls, AuthError)
    assert not issubclass(UsernamePolicyError, PasswordPolicyError)
    assert not issubclass(PasswordPolicyError, UsernamePolicyError)


def test_exception_carries_code_and_fixed_message():
    exc = UsernamePolicyError("username_too_short")
    assert exc.code == "username_too_short"
    assert exc.message == str(exc) == "Username is too short."


def test_taken_error_has_its_own_code():
    exc = UsernameTakenError()
    assert exc.code == "username_taken"
    assert exc.message == "Username is already taken."


def test_unknown_code_is_rejected():
    with pytest.raises(KeyError):
        AuthError("no_such_code")


def test_messages_are_distinct_plain_sentences():
    messages = services._MESSAGES
    assert len(set(messages.values())) == len(messages)
    for code, text in messages.items():
        assert code == code.lower() and " " not in code
        assert text.isascii() and text.endswith(".")
        assert "{" not in text and "%" not in text


# --------------------------------------------------------------------------
# normalize_username
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("alice", "alice"),
        ("Alice", "alice"),
        ("  alice  ", "alice"),
        ("\talice\n", "alice"),
        ("ALICE_01", "alice_01"),
        ("a.b-c_d", "a.b-c_d"),
        ("abc", "abc"),
        ("a1b", "a1b"),
        ("007", "007"),
        ("x" * USERNAME_MAX, "x" * USERNAME_MAX),
        ("a" + "-" * 30 + "b", "a" + "-" * 30 + "b"),
    ],
)
def test_normalize_username_accepts(raw, expected):
    assert normalize_username(raw) == expected


def test_normalize_username_is_idempotent():
    once = normalize_username("  MiXeD.Name ")
    assert normalize_username(once) == once


@pytest.mark.parametrize("raw", ["", " ", "a", "ab", "  ab  "])
def test_username_too_short(raw):
    with pytest.raises(UsernamePolicyError) as info:
        normalize_username(raw)
    assert code_of(info) == "username_too_short"


@pytest.mark.parametrize(
    "raw", ["x" * (USERNAME_MAX + 1), "x" * 500, "  " + "x" * 33 + "  "]
)
def test_username_too_long(raw):
    with pytest.raises(UsernamePolicyError) as info:
        normalize_username(raw)
    assert code_of(info) == "username_too_long"


@pytest.mark.parametrize(
    "raw",
    [
        "ali ce",
        "ali\tce",
        "ali\nce",
        "ali\x00ce",
        "ali@ce",
        "ali/ce",
        "ali\\ce",
        "ali:ce",
        "ali*ce",
        "ali'ce",
        'ali"ce',
        "ali<b>ce",
        "ali;ce",
        "ali,ce",
        "ali+ce",
        "ali=ce",
        "ali%ce",
        "aliüce",  # u with diaeresis
        "ünal",
        "аlice",  # Cyrillic a
        "ａｂｃ",  # fullwidth abc
        "Kelvin",  # Kelvin sign: lower() would turn it into "k"
        "İstanbul",  # dotted capital I
        "ſam",  # long s
        "ali\U0001f600",
        "　　alice　x",
    ],
)
def test_username_invalid_characters(raw):
    with pytest.raises(UsernamePolicyError) as info:
        normalize_username(raw)
    assert code_of(info) == "username_invalid_characters"


def test_non_ascii_is_checked_before_lowercasing():
    # If lower() ran first, the Kelvin sign would become "k" and be accepted.
    assert "K".lower() == "k"
    with pytest.raises(UsernamePolicyError):
        normalize_username("KKK")


def test_non_ascii_beats_length_checks():
    with pytest.raises(UsernamePolicyError) as info:
        normalize_username("ü")
    assert code_of(info) == "username_invalid_characters"


@pytest.mark.parametrize(
    "raw",
    [
        ".abc",
        "abc.",
        "-abc",
        "abc-",
        "_abc",
        "abc_",
        "..abc",
        "a.b.",
        "...",
        "---",
    ],
)
def test_username_must_start_and_end_with_alphanumeric(raw):
    with pytest.raises(UsernamePolicyError) as info:
        normalize_username(raw)
    assert code_of(info) == "username_bad_edge"


@pytest.mark.parametrize("raw", [None, 5, 5.0, b"alice", ["alice"], object()])
def test_normalize_username_rejects_non_strings(raw):
    with pytest.raises(TypeError):
        normalize_username(raw)


def test_username_errors_do_not_echo_input():
    secret = "SeCrEt Name!"
    with pytest.raises(UsernamePolicyError) as info:
        normalize_username(secret)
    assert secret not in str(info.value)
    assert secret.lower() not in str(info.value)


# --------------------------------------------------------------------------
# validate_password
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "password",
    [
        GOOD,
        "x" * PASSWORD_MIN,
        "x" * PASSWORD_MAX,
        "abcdefghi ",  # trailing space counts: it is not stripped
        " abcdefghi",
        "with spaces inside it",
        "pässwörd-ñandú",
        "密码密码密码密码密码",
        "emoji-\U0001f600\U0001f600\U0001f600-ok",
        "aaaaaaaaaaaaaaaaaaaaaaa",  # no composition rules
        "é" * 128,  # 256 raw characters, 128 after NFKC
    ],
)
def test_valid_passwords(password):
    assert validate_password(password) is None


@pytest.mark.parametrize(
    "password", ["", "a", "x" * (PASSWORD_MIN - 1), "é" * 5]
)
def test_password_too_short(password):
    with pytest.raises(PasswordPolicyError) as info:
        validate_password(password)
    assert code_of(info) == "password_too_short"


def test_length_is_counted_after_normalization():
    # 5 decomposed letters are 10 raw characters but only 5 after NFKC.
    assert len("é" * 5) == PASSWORD_MIN
    # 65 ligatures are 65 raw characters but 130 after NFKC.
    with pytest.raises(PasswordPolicyError) as info:
        validate_password("ﬁ" * 65)
    assert code_of(info) == "password_too_long"
    with pytest.raises(PasswordPolicyError) as info:
        validate_password("é" * (PASSWORD_MAX + 1))
    assert code_of(info) == "password_too_long"


@pytest.mark.parametrize(
    "password",
    [
        "x" * (PASSWORD_MAX + 1),
        "x" * 10_000,
        "x" * (PASSWORD_MAX * 8),
        "x" * (PASSWORD_MAX * 8 + 1),
    ],
)
def test_password_too_long(password):
    with pytest.raises(PasswordPolicyError) as info:
        validate_password(password)
    assert code_of(info) == "password_too_long"


def test_huge_input_is_refused_before_normalization(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("normalize must not see huge input")

    stub = types.SimpleNamespace(
        normalize=boom, category=unicodedata.category
    )
    # Replace only the module's own reference; pytest uses the real one.
    monkeypatch.setattr(services, "unicodedata", stub)
    with pytest.raises(PasswordPolicyError) as info:
        validate_password("x" * (PASSWORD_MAX * 8 + 1))
    assert code_of(info) == "password_too_long"


@pytest.mark.parametrize(
    "bad",
    ["\x00", "\t", "\n", "\r", "\x1b", "\x7f", "\u0085", "\ud800", "\udfff"],
)
def test_password_invalid_characters(bad):
    password = "valid-start" + bad + "valid-end"
    with pytest.raises(PasswordPolicyError) as info:
        validate_password(password)
    assert code_of(info) == "password_invalid_characters"


def test_invalid_characters_win_over_too_short():
    with pytest.raises(PasswordPolicyError) as info:
        validate_password("a\x00")
    assert code_of(info) == "password_invalid_characters"


@pytest.mark.parametrize(
    ("password", "username"),
    [
        ("longusername", "longusername"),
        ("LongUserName", "longusername"),
        ("longusername", "LongUserName"),
        ("longusername", "  longusername  "),
    ],
)
def test_password_same_as_username(password, username):
    with pytest.raises(PasswordPolicyError) as info:
        validate_password(password, username)
    assert code_of(info) == "password_same_as_username"


def test_username_check_is_skipped_without_username():
    assert validate_password("longusername") is None
    assert validate_password("longusername", None) is None
    assert validate_password("longusername", "someoneelse") is None


@pytest.mark.parametrize("username", [5, b"x", ["x"]])
def test_validate_password_rejects_non_string_username(username):
    with pytest.raises(TypeError):
        validate_password(GOOD, username)


@pytest.mark.parametrize(
    "password",
    [
        "password123",
        "Password123",
        "PASSWORD123",
        "1234567890",
        "QWERTYUIOP",
        "1q2w3e4r5t",
        "administrator",
        "ＰＡＳＳＷＯＲＤ１２３",
    ],
)
def test_common_passwords_are_refused(password):
    with pytest.raises(PasswordPolicyError) as info:
        validate_password(password)
    assert code_of(info) == "password_too_common"


@pytest.mark.parametrize("entry", sorted(services._COMMON_PASSWORDS))
def test_every_common_password_is_refused(entry):
    for variant in (entry, entry.upper(), entry.title()):
        with pytest.raises(PasswordPolicyError) as info:
            validate_password(variant)
        assert code_of(info) == "password_too_common"


@pytest.mark.parametrize("password", [None, 12345, b"password123", ["x"]])
def test_validate_password_rejects_non_strings(password):
    with pytest.raises(TypeError):
        validate_password(password)


def test_password_errors_do_not_echo_input():
    password = "SuperSecret\x00Value"
    with pytest.raises(PasswordPolicyError) as info:
        validate_password(password)
    assert "SuperSecret" not in str(info.value)


# --------------------------------------------------------------------------
# hash_password / verify_password
# --------------------------------------------------------------------------


def test_hash_is_argon2id_and_fits_the_column(real_hasher):
    hashed = hash_password(GOOD)
    assert hashed.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert len(hashed) == 97
    assert len(hashed) <= User.__table__.c.password_hash.type.length
    assert GOOD not in hashed


def test_library_defaults_are_used():
    # No custom parameters were passed to the module-level hasher.
    assert services.PasswordHasher is PasswordHasher
    source = inspect.getsource(services)
    assert "PasswordHasher()" in source


def test_hashes_are_salted():
    assert hash_password(GOOD) != hash_password(GOOD)


def test_verify_roundtrip():
    hashed = hash_password(GOOD)
    assert verify_password(hashed, GOOD) is True
    assert verify_password(hashed, GOOD + "x") is False
    assert verify_password(hashed, "") is False
    assert verify_password(hashed, GOOD.upper()) is False


def test_verify_treats_equivalent_unicode_as_equal():
    composed = "café-au-lait"
    decomposed = "café-au-lait"
    hashed = hash_password(composed)
    assert verify_password(hashed, decomposed) is True
    assert verify_password(hash_password(decomposed), composed) is True
    fullwidth = "ＰＡＳＳＷＯＲＤ"
    assert verify_password(hash_password(fullwidth), "PASSWORD") is True


@pytest.mark.parametrize(
    "stored",
    [
        "",
        "garbage",
        "hash-" + "x" * 20,
        "$argon2id$garbage",
        "$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$",
        "$2b$12$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234",
    ],
)
def test_verify_with_unreadable_hash_is_false(stored):
    assert verify_password(stored, GOOD) is False


@pytest.mark.parametrize(
    "password",
    ["x" * (PASSWORD_MAX + 1), "x" * 5000, "bad\x00pass", "\ud800" * 12],
)
def test_verify_with_unusable_password_is_false_without_hashing(
    hasher, password
):
    hashed = hash_password(GOOD)
    hasher.reset()
    assert verify_password(hashed, password) is False
    assert hasher.verify_calls == []


@pytest.mark.parametrize(
    ("stored", "password"),
    [
        (None, GOOD),
        (b"x", GOOD),
        (5, GOOD),
        ("x", None),
        ("x", b"pw"),
        ("x", 5),
    ],
)
def test_verify_rejects_non_strings(stored, password):
    with pytest.raises(TypeError):
        verify_password(stored, password)


@pytest.mark.parametrize(
    "password", ["x" * (PASSWORD_MAX + 1), "bad\x00pass", "\ud800"]
)
def test_hash_rejects_unusable_passwords(password):
    with pytest.raises(PasswordPolicyError):
        hash_password(password)


@pytest.mark.parametrize("password", [None, 5, b"pw"])
def test_hash_rejects_non_strings(password):
    with pytest.raises(TypeError):
        hash_password(password)


def test_unexpected_hasher_errors_are_not_swallowed(monkeypatch, alice):
    class Broken:
        def verify(self, stored_hash, password):
            raise RuntimeError("boom")

    monkeypatch.setattr(services, "_HASHER", Broken())
    with pytest.raises(RuntimeError):
        verify_password("x", GOOD)
    with pytest.raises(RuntimeError):
        authenticate("alice", GOOD)


def test_dummy_hash_is_not_built_at_import_time():
    tree = ast.parse(inspect.getsource(services))
    values = [
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(getattr(t, "id", None) == "_dummy" for t in node.targets)
    ]
    assert len(values) == 1
    assert isinstance(values[0], ast.Constant) and values[0].value is None


def test_hash_receives_the_normalized_password(hasher):
    hash_password("café-au-lait")
    assert hasher.hash_calls == ["café-au-lait"]


# --------------------------------------------------------------------------
# register_user
# --------------------------------------------------------------------------


def test_register_saves_and_returns_the_user(hasher):
    user = register_user("alice", GOOD)
    assert isinstance(user, User)
    assert user.id is not None
    assert user.username == "alice"
    assert user.created_at is not None
    assert hasher.hash_calls == [GOOD]
    db.session.remove()
    row = db.session.get(User, user.id)
    assert row is not None and row.username == "alice"
    assert row.password_hash.startswith("$argon2id$")
    assert GOOD not in row.password_hash
    assert verify_password(row.password_hash, GOOD) is True


def test_register_normalizes_the_username():
    user = register_user("  Alice.Smith ", GOOD)
    assert user.username == "alice.smith"


def test_register_commits_the_transaction():
    user = register_user("alice", GOOD)
    user_id = user.id
    db.session.rollback()  # would undo an uncommitted insert
    assert db.session.get(User, user_id) is not None


@pytest.mark.parametrize("second", ["alice", "ALICE", "  Alice  "])
def test_duplicate_username_is_refused(second):
    register_user("alice", GOOD)
    with pytest.raises(UsernameTakenError) as info:
        register_user(second, "another long password")
    assert info.value.code == "username_taken"
    assert db.session.query(User).count() == 1


def test_session_is_usable_after_a_duplicate():
    register_user("alice", GOOD)
    with pytest.raises(UsernameTakenError):
        register_user("alice", GOOD)
    bob = register_user("bob.b", GOOD)
    assert bob.id is not None
    assert db.session.query(User).count() == 2


def test_taken_error_hides_the_hash_and_the_cause():
    register_user("alice", GOOD)
    with pytest.raises(UsernameTakenError) as info:
        register_user("alice", GOOD)
    exc = info.value
    assert exc.__context__ is None
    assert exc.__cause__ is None
    assert "argon2" not in str(exc)


def test_other_integrity_errors_are_not_mislabelled(monkeypatch):
    def failing_commit():
        raise IntegrityError("INSERT", {"password_hash": "x"}, Exception("x"))

    monkeypatch.setattr(db.session, "commit", failing_commit)
    with pytest.raises(IntegrityError):
        register_user("carol", GOOD)
    monkeypatch.undo()
    assert len(db.session.new) == 0
    assert db.session.query(User).count() == 0
    assert register_user("carol", GOOD).id is not None


@pytest.mark.parametrize(
    ("username", "code"),
    [
        ("a", "username_too_short"),
        ("x" * 33, "username_too_long"),
        ("bad name", "username_invalid_characters"),
        (".dot", "username_bad_edge"),
    ],
)
def test_register_rejects_bad_usernames(username, code):
    with pytest.raises(UsernamePolicyError) as info:
        register_user(username, GOOD)
    assert info.value.code == code
    assert db.session.query(User).count() == 0


@pytest.mark.parametrize(
    ("password", "code"),
    [
        ("short", "password_too_short"),
        ("x" * 129, "password_too_long"),
        ("bad\x00password", "password_invalid_characters"),
        ("password123", "password_too_common"),
        ("alice.smith", "password_same_as_username"),
        ("ALICE.SMITH", "password_same_as_username"),
    ],
)
def test_register_rejects_bad_passwords(password, code, hasher):
    with pytest.raises(PasswordPolicyError) as info:
        register_user(" Alice.Smith ", password)
    assert info.value.code == code
    assert db.session.query(User).count() == 0
    assert hasher.hash_calls == []  # nothing is hashed for a refused password


@pytest.mark.parametrize(
    ("username", "password"),
    [(None, GOOD), (5, GOOD), ("alice", None), ("alice", b"x" * 12)],
)
def test_register_rejects_non_strings(username, password):
    with pytest.raises(TypeError):
        register_user(username, password)
    assert db.session.query(User).count() == 0


def test_register_checks_the_username_before_the_password():
    with pytest.raises(UsernamePolicyError):
        register_user("a", "short")


# --------------------------------------------------------------------------
# authenticate
# --------------------------------------------------------------------------


def test_authenticate_success(alice, hasher):
    user = authenticate("alice", GOOD)
    assert user is not None
    assert user.id == alice.id
    assert len(hasher.verify_calls) == 1
    assert hasher.verify_calls[0] == (alice.password_hash, GOOD)
    # The dummy hash is not built when it is not needed.
    assert hasher.hash_calls == []


@pytest.mark.parametrize("name", ["ALICE", "  alice  ", "Alice"])
def test_authenticate_normalizes_the_username(alice, name):
    user = authenticate(name, GOOD)
    assert user is not None and user.id == alice.id


def test_authenticate_accepts_equivalent_unicode_password():
    register_user("zoe", "café-au-lait")
    assert authenticate("zoe", "café-au-lait") is not None


# username, password, which hash must be verified
FAILURES = [
    ("alice", "wrong password!", "real"),
    ("alice", GOOD + "x", "real"),
    ("alice", GOOD.upper(), "real"),
    ("alice", "", "real"),
    ("alice", "x" * PASSWORD_MAX, "real"),
    ("alice", "x" * (PASSWORD_MAX + 1), "dummy"),
    ("alice", "x" * 100_000, "dummy"),
    ("alice", "bad\x00password", "dummy"),
    ("alice", "bad\npassword", "dummy"),
    ("alice", "\ud800" * 12, "dummy"),
    ("nobody", GOOD, "dummy"),
    ("nobody", "", "dummy"),
    ("a", GOOD, "dummy"),
    ("", GOOD, "dummy"),
    ("bad name", GOOD, "dummy"),
    ("ünal", GOOD, "dummy"),
    ("Klice", GOOD, "dummy"),
    (".alice", GOOD, "dummy"),
    ("x" * 40, GOOD, "dummy"),
    ("ali\x00ce", GOOD, "dummy"),
]


@pytest.mark.parametrize(("username", "password", "target"), FAILURES)
def test_every_failure_returns_none_after_one_verification(
    alice, hasher, username, password, target
):
    assert authenticate(username, password) is None
    assert len(hasher.verify_calls) == 1
    used_hash, used_password = hasher.verify_calls[0]
    if target == "real":
        assert used_hash == alice.password_hash
    else:
        assert used_hash != alice.password_hash
        assert used_hash.startswith("$argon2id$")
        # Unusable or oversized input itself is never hashed.
        assert used_password != password
        assert len(used_password) <= PASSWORD_MAX


def test_failures_are_indistinguishable_to_the_caller(alice):
    results = [authenticate(u, p) for u, p, _ in FAILURES]
    assert all(result is None for result in results)


def test_other_users_password_does_not_work(alice):
    register_user("bob.b", "another long password")
    assert authenticate("alice", "another long password") is None
    assert authenticate("bob.b", GOOD) is None
    assert authenticate("bob.b", "another long password") is not None


def test_dummy_hash_is_built_once_and_reused(alice, hasher):
    for name in ("nobody", "ghost", "a"):
        assert authenticate(name, GOOD) is None
    assert len(hasher.hash_calls) == 1
    assert len(hasher.verify_calls) == 3
    assert len({call[0] for call in hasher.verify_calls}) == 1
    assert hasher.verify_calls[0][0] == services._dummy[1]


def test_dummy_hash_is_made_lazily():
    assert services._dummy is None
    register_user("alice", GOOD)
    assert services._dummy is None
    authenticate("alice", GOOD)
    assert services._dummy is None
    authenticate("nobody", GOOD)
    assert services._dummy is not None


def test_dummy_password_is_random_and_never_logs_anyone_in(alice):
    secret, dummy_hash = services._dummy_credentials()
    assert len(secret) >= 32
    assert verify_password(dummy_hash, secret) is True
    assert authenticate("nobody", secret) is None
    assert authenticate("alice", secret) is None


def test_dummy_credentials_differ_between_processes(monkeypatch):
    first = services._dummy_credentials()
    monkeypatch.setattr(services, "_dummy", None)
    second = services._dummy_credentials()
    assert first[0] != second[0]
    assert first[1] != second[1]


def test_dummy_hash_has_the_same_parameters_as_real_hashes(real_hasher):
    user = register_user("alice", GOOD)
    real_hasher.reset()
    assert authenticate("nobody", GOOD) is None
    dummy_hash = real_hasher.verify_calls[0][0]
    assert dummy_hash != user.password_hash
    assert extract_parameters(dummy_hash) == extract_parameters(
        user.password_hash
    )


def test_damaged_stored_hash_is_a_plain_failure(hasher, make_user):
    make_user("erin.e", "hash-" + "x" * 20)
    assert authenticate("erin.e", GOOD) is None
    assert len(hasher.verify_calls) == 1


@pytest.mark.parametrize(
    ("username", "password"),
    [
        (None, GOOD),
        (5, GOOD),
        ("alice", None),
        ("alice", b"x"),
        (b"alice", GOOD),
    ],
)
def test_authenticate_rejects_non_strings(alice, username, password):
    with pytest.raises(TypeError):
        authenticate(username, password)


@pytest.mark.parametrize(
    ("username", "password"), [(None, GOOD), ("alice", None), ("alice", 5)]
)
def test_authenticate_checks_types_before_touching_the_database(
    alice, monkeypatch, username, password
):
    def no_queries(*args, **kwargs):
        raise AssertionError("the database must not be queried")

    monkeypatch.setattr(db.session, "execute", no_queries)
    with pytest.raises(TypeError):
        authenticate(username, password)


def test_authenticate_returns_none_not_false(alice):
    assert authenticate("alice", "wrong password!") is None
    assert authenticate("nobody", GOOD) is None


# --------------------------------------------------------------------------
# get_user
# --------------------------------------------------------------------------


def test_get_user_returns_the_user(alice):
    found = get_user(alice.id)
    assert found is not None and found.id == alice.id


def test_get_user_unknown_id_is_none(alice):
    assert get_user(alice.id + 1000) is None


@pytest.mark.parametrize(
    "value",
    [0, -1, 2**63, 2**70, -(2**70), "1", b"1", None, 1.0, True, False, [1]],
)
def test_get_user_rejects_odd_values_quietly(alice, value):
    assert alice.id == 1  # so True would otherwise find the user
    assert get_user(value) is None


def test_get_user_accepts_the_largest_sqlite_integer(alice):
    assert get_user(2**63 - 1) is None  # valid range, simply no such row
