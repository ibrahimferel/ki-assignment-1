"""Tests for app/config.py.

``Config`` is always built from a plain dict here, so the real environment
and the real ``.env`` file (which holds secrets) are never read.
"""

import tempfile
from pathlib import Path

import pytest

from app import config as config_module
from app import create_app
from app.config import BASE_DIR, Config, ConfigError, TestingConfig

SECRET = "s" * 40
MASTER = "ab" * 32  # 64 hex characters = 32 bytes
MIB = 1024 * 1024


def make_env(**changes):
    env = {"SECRET_KEY": SECRET, "MASTER_KEY": MASTER}
    env.update(changes)
    return {key: value for key, value in env.items() if value is not None}


def refused(env, expected_word):
    with pytest.raises(ConfigError) as caught:
        Config(environ=env)
    assert expected_word in str(caught.value)
    return str(caught.value)


def upper_case_settings(config):
    return {name for name in dir(config) if name.isupper()}


# ----------------------------------------------------------------- defaults


def test_a_minimal_environment_gives_the_documented_defaults():
    config = Config(environ=make_env())

    assert config.SECRET_KEY == SECRET
    assert config.MASTER_KEY == bytes.fromhex(MASTER)
    assert len(config.MASTER_KEY) == 32
    assert config.DEBUG is False
    assert config.MAX_CONTENT_LENGTH == 50 * MIB
    assert config.SQLALCHEMY_DATABASE_URI == "sqlite:///app.db"
    assert config.STORAGE_DIR == BASE_DIR / "instance" / "storage"
    assert config.SQLALCHEMY_ENGINE_OPTIONS == {"hide_parameters": True}


def test_config_exposes_exactly_the_documented_settings():
    assert upper_case_settings(Config(environ=make_env())) == {
        "SECRET_KEY",
        "MASTER_KEY",
        "DEBUG",
        "SQLALCHEMY_DATABASE_URI",
        "MAX_CONTENT_LENGTH",
        "STORAGE_DIR",
        "SQLALCHEMY_ENGINE_OPTIONS",
    }


def test_each_config_has_its_own_engine_options_dict():
    first = Config(environ=make_env())
    second = Config(environ=make_env())
    assert (
        first.SQLALCHEMY_ENGINE_OPTIONS is not second.SQLALCHEMY_ENGINE_OPTIONS
    )


def test_config_error_is_a_runtime_error():
    assert issubclass(ConfigError, RuntimeError)


# --------------------------------------------------------------- SECRET_KEY


@pytest.mark.parametrize(
    "value", [None, "", "   ", "k" * 31, " " + "k" * 30 + " "]
)
def test_a_missing_or_short_secret_key_is_refused(value):
    message = refused(make_env(SECRET_KEY=value), "SECRET_KEY")
    assert "token_hex" in message  # the message says how to fix it


def test_secret_key_boundaries_and_stripping():
    assert Config(environ=make_env(SECRET_KEY="k" * 32)).SECRET_KEY == "k" * 32
    padded = Config(environ=make_env(SECRET_KEY="  " + "k" * 32 + "  "))
    assert padded.SECRET_KEY == "k" * 32


def test_the_error_never_repeats_the_secret_key_value():
    message = refused(make_env(SECRET_KEY="supersecret123"), "SECRET_KEY")
    assert "supersecret123" not in message


# --------------------------------------------------------------- MASTER_KEY


@pytest.mark.parametrize("value", [None, "", "   "])
def test_a_missing_master_key_is_refused(value):
    refused(make_env(MASTER_KEY=value), "MASTER_KEY is missing")


@pytest.mark.parametrize(
    "value",
    [
        "ab" * 31,
        "ab" * 33,
        "g" * 64,
        "ab" * 15 + "  " + "ab" * 16,  # 64 characters, but only 31 bytes
        "0x" + "a" * 62,
    ],
    ids=["too-short", "too-long", "not-hex", "inner-space", "0x-prefix"],
)
def test_a_malformed_master_key_is_refused(value):
    message = refused(make_env(MASTER_KEY=value), "64 hexadecimal")
    assert value not in message


def test_master_key_may_be_upper_case_or_padded():
    config = Config(environ=make_env(MASTER_KEY="  " + MASTER.upper() + " "))
    assert config.MASTER_KEY == bytes.fromhex(MASTER)


@pytest.mark.parametrize("transform", [str, str.upper])
def test_master_key_must_differ_from_secret_key(transform):
    same = "cd" * 32
    env = make_env(SECRET_KEY=same, MASTER_KEY=transform(same))
    refused(env, "must be different")


# -------------------------------------------------------------- FLASK_DEBUG


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("1", True),
        ("true", True),
        ("TRUE", True),
        (" yes ", True),
        ("on", True),
        ("0", False),
        ("false", False),
        ("No", False),
        ("off", False),
        ("", False),
    ],
)
def test_flask_debug_accepts_only_clear_values(raw, expected):
    assert Config(environ=make_env(FLASK_DEBUG=raw)).DEBUG is expected


@pytest.mark.parametrize("raw", ["maybe", "2", "enabled", "y"])
def test_flask_debug_rejects_anything_else(raw):
    refused(make_env(FLASK_DEBUG=raw), "FLASK_DEBUG")


# ----------------------------------------------------------- MAX_UPLOAD_MB


@pytest.mark.parametrize(
    "raw, megabytes", [("7", 7), (" 100 ", 100), ("", 50), ("1", 1)]
)
def test_max_upload_mb(raw, megabytes):
    config = Config(environ=make_env(MAX_UPLOAD_MB=raw))
    assert config.MAX_CONTENT_LENGTH == megabytes * MIB


@pytest.mark.parametrize("raw", ["0", "-5", "abc", "1.5", "5MB"])
def test_a_bad_max_upload_mb_is_refused(raw):
    refused(make_env(MAX_UPLOAD_MB=raw), "MAX_UPLOAD_MB")


# ------------------------------------------------------------- DATABASE_URL


def test_database_url_overrides_the_default_and_blank_falls_back():
    assert (
        Config(environ=make_env(DATABASE_URL="sqlite:///other.db"))
        .SQLALCHEMY_DATABASE_URI == "sqlite:///other.db"
    )
    assert (
        Config(environ=make_env(DATABASE_URL="  "))
        .SQLALCHEMY_DATABASE_URI == "sqlite:///app.db"
    )


# -------------------------------------------------------------- STORAGE_DIR


def test_a_relative_storage_dir_is_relative_to_the_project_not_the_cwd(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    config = Config(environ=make_env(STORAGE_DIR="vault/files"))
    assert config.STORAGE_DIR == BASE_DIR / "vault" / "files"
    assert not (BASE_DIR / "vault").exists()  # config creates nothing


def test_an_absolute_storage_dir_is_kept_and_normalised(tmp_path):
    raw = str(tmp_path / "a" / ".." / "store")
    config = Config(environ=make_env(STORAGE_DIR=raw))
    assert config.STORAGE_DIR == tmp_path / "store"
    assert not (tmp_path / "store").exists()


def test_a_storage_dir_that_is_a_file_is_refused(tmp_path):
    target = tmp_path / "note.txt"
    target.write_text("x")
    refused(make_env(STORAGE_DIR=str(target)), "STORAGE_DIR")


def test_an_existing_folder_is_accepted(tmp_path):
    config = Config(environ=make_env(STORAGE_DIR=str(tmp_path)))
    assert config.STORAGE_DIR == tmp_path


# ---------------------------------------------- the real-environment route


@pytest.fixture()
def real_environment(monkeypatch, tmp_path):
    """Use os.environ, but never read the project's real .env file."""
    # Run from elsewhere: .env must be found through BASE_DIR, not the cwd.
    monkeypatch.chdir(tmp_path)
    loaded = []
    monkeypatch.setattr(
        config_module, "load_dotenv", lambda path: loaded.append(path)
    )
    for name in (
        "SECRET_KEY",
        "MASTER_KEY",
        "FLASK_DEBUG",
        "MAX_UPLOAD_MB",
        "DATABASE_URL",
        "STORAGE_DIR",
    ):
        monkeypatch.delenv(name, raising=False)
    return loaded


def test_config_without_environ_reads_os_environ_after_loading_dotenv(
    real_environment, monkeypatch
):
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("MASTER_KEY", MASTER)
    monkeypatch.setenv("FLASK_DEBUG", "1")

    config = Config()

    assert config.SECRET_KEY == SECRET and config.DEBUG is True
    assert real_environment == [BASE_DIR / ".env"]


def test_config_without_environ_refuses_when_nothing_is_set(real_environment):
    with pytest.raises(ConfigError, match="SECRET_KEY"):
        Config()


# ------------------------------------------------------------ TestingConfig


def test_testing_config_exposes_exactly_the_documented_settings():
    assert upper_case_settings(TestingConfig()) == {
        "TESTING",
        "DEBUG",
        "SQLALCHEMY_DATABASE_URI",
        "MAX_CONTENT_LENGTH",
        "SECRET_KEY",
        "MASTER_KEY",
        "STORAGE_DIR",
        "SQLALCHEMY_ENGINE_OPTIONS",
    }


def test_testing_config_values():
    config = TestingConfig()
    assert config.TESTING is True and config.DEBUG is False
    assert config.SQLALCHEMY_DATABASE_URI == "sqlite:///:memory:"
    assert config.MAX_CONTENT_LENGTH == 50 * MIB
    assert config.SQLALCHEMY_ENGINE_OPTIONS == {"hide_parameters": True}


def test_testing_config_makes_fresh_random_keys_each_time():
    first, second = TestingConfig(), TestingConfig()
    assert first.SECRET_KEY != second.SECRET_KEY
    assert first.MASTER_KEY != second.MASTER_KEY
    assert len(first.SECRET_KEY) == 64 and len(first.MASTER_KEY) == 32
    assert first.SECRET_KEY != first.MASTER_KEY.hex()
    assert (
        first.SQLALCHEMY_ENGINE_OPTIONS
        is not second.SQLALCHEMY_ENGINE_OPTIONS
    )


def test_testing_config_storage_dir_is_unique_temporary_and_not_created():
    first, second = TestingConfig(), TestingConfig()
    assert first.STORAGE_DIR != second.STORAGE_DIR
    assert Path(tempfile.gettempdir()) in first.STORAGE_DIR.parents
    assert not first.STORAGE_DIR.exists()


def test_testing_config_ignores_the_environment(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///REAL.db")
    monkeypatch.setenv("SECRET_KEY", "z" * 64)
    monkeypatch.setenv("STORAGE_DIR", "/should/not/be/used")
    config = TestingConfig()
    assert config.SQLALCHEMY_DATABASE_URI == "sqlite:///:memory:"
    assert config.SECRET_KEY != "z" * 64
    assert str(config.STORAGE_DIR) != "/should/not/be/used"


def test_pytest_does_not_try_to_collect_testing_config():
    assert TestingConfig.__test__ is False


# ------------------------------------------------- the settings reach Flask


def test_all_settings_reach_flask_config(tmp_path):
    env = make_env(
        DATABASE_URL="sqlite:///:memory:",
        STORAGE_DIR=str(tmp_path / "store"),
        MAX_UPLOAD_MB="9",
        FLASK_DEBUG="1",
    )
    flask_app = create_app(Config(environ=env))

    assert flask_app.config["SECRET_KEY"] == SECRET
    assert flask_app.config["MASTER_KEY"] == bytes.fromhex(MASTER)
    assert flask_app.config["MAX_CONTENT_LENGTH"] == 9 * MIB
    assert flask_app.config["STORAGE_DIR"] == tmp_path / "store"
    assert flask_app.config["SQLALCHEMY_ENGINE_OPTIONS"] == {
        "hide_parameters": True
    }
    assert flask_app.debug is True


def test_the_default_storage_dir_sits_inside_flasks_instance_folder():
    flask_app = create_app(TestingConfig())
    instance = Path(flask_app.instance_path).resolve()
    assert instance == BASE_DIR / "instance"
    assert config_module.DEFAULT_STORAGE_DIR == instance / "storage"
