"""Skenario pemakaian nyata, lewat aplikasi ASLI dari ``create_app()``.

Berbeda dengan test_storage_routes.py, file ini TIDAK mendaftarkan blueprint
storage sendiri: kalau ``create_app()`` lupa mendaftarkannya, semua tes di
sini gagal, persis seperti yang akan dialami pengguna sungguhan.

Isi:
* perjalanan lengkap pengguna: daftar -> login -> unggah -> daftar file ->
  unduh (AES/DES/RC4) -> hapus -> file ciphertext ikut hilang dari disk;
* setiap format yang didukung, dibuat dengan struktur file yang realistis;
* isi biner sembarang (banyak byte \\n dan \\r) di batas-batas ukuran blok;
* plaintext tidak pernah muncul di disk maupun di database;
* data tetap terbaca setelah aplikasi di-restart (DB file + kunci sama),
  dan kunci master yang salah memberi error rapi, bukan 500;
* batas ukuran unggahan mengikuti MAX_UPLOAD_MB;
* foto JPEG dari ponsel yang membawa data tambahan setelah penanda akhir.
"""

import io
import os
import re
import sqlite3
import struct
import zipfile
import zlib

import pytest
from argon2 import PasswordHasher

from app import create_app
from app.auth import services as auth_services
from app.config import TestingConfig
from app.database import init_db
from app.extensions import db
from app.storage import validation

PASSWORD = "correct horse battery"
TOKEN = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')


# ------------------------------------------------------------ file contoh


def png_bytes():
    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(
            ">I", zlib.crc32(body) & 0xFFFFFFFF
        )

    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    pixels = zlib.compress(b"\x00\xff\x00\x00")
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", pixels)
        + chunk(b"IEND", b"")
    )


def jpeg_bytes():
    app0 = b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    return b"\xff\xd8" + app0 + os.urandom(512) + b"\xff\xd9"


def pdf_bytes():
    return (
        b"%PDF-1.4\r\n1 0 obj << /Type /Catalog >> endobj\r\n"
        b"trailer << /Root 1 0 R >>\r\n%%EOF\r\n"
    )


def ole_bytes(stream_name):
    magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    return magic + b"\x00" * 504 + stream_name.encode("utf-16-le") + b"\x00" * 64


def office_zip(main_part):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr(main_part, "<root>isi dokumen</root>")
    return buffer.getvalue()


def mp4_bytes(payload=b""):
    return b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom" + payload


FORMATS = {
    "id_card-png": ("id_card", "ktp.png", png_bytes),
    "id_card-jpg": ("id_card", "KTP_Scan.JPG", jpeg_bytes),
    "id_card-jpeg": ("id_card", "ktp.jpeg", jpeg_bytes),
    "document-pdf": ("document", "Laporan Akhir.pdf", pdf_bytes),
    "document-doc": ("document", "surat.doc", lambda: ole_bytes("WordDocument")),
    "document-xls": ("document", "nilai.xls", lambda: ole_bytes("Workbook")),
    "document-docx": ("document", "skripsi.docx", lambda: office_zip("word/document.xml")),
    "document-xlsx": ("document", "anggaran.xlsx", lambda: office_zip("xl/workbook.xml")),
    "video-mp4": ("video", "rekaman.mp4", lambda: mp4_bytes(os.urandom(4096))),
}


# --------------------------------------------------------------- helpers


@pytest.fixture(autouse=True)
def cheap_hasher(monkeypatch):
    monkeypatch.setattr(
        auth_services,
        "_HASHER",
        PasswordHasher(time_cost=1, memory_cost=8, parallelism=1),
    )
    monkeypatch.setattr(auth_services, "_dummy", None)


def token(browser):
    page = browser.get("/auth/login").get_data(as_text=True)
    found = TOKEN.search(page)
    if found is None:  # sudah login: halaman login mengalihkan ke "/"
        found = TOKEN.search(browser.get("/").get_data(as_text=True))
    assert found is not None, "CSRF token tidak ditemukan"
    return found[1]


def post(browser, path, **kwargs):
    headers = kwargs.pop("headers", {})
    headers["X-CSRFToken"] = token(browser)
    return browser.post(path, headers=headers, **kwargs)


def register_and_login(browser, username):
    page = browser.get("/auth/register").get_data(as_text=True)
    response = browser.post(
        "/auth/register",
        data={
            "csrf_token": TOKEN.search(page)[1],
            "username": username,
            "password": PASSWORD,
            "confirm": PASSWORD,
        },
    )
    assert response.status_code == 302, "registrasi lewat form gagal"
    response = post(
        browser, "/auth/login", data={"username": username, "password": PASSWORD}
    )
    assert response.status_code == 302, "login lewat form gagal"


def upload(browser, kind, filename, data):
    return post(
        browser,
        "/storage/upload",
        data={"kind": kind, "file": (io.BytesIO(data), filename)},
        content_type="multipart/form-data",
    )


def storage_files(flask_app):
    folder = flask_app.config["STORAGE_DIR"]
    if not folder.exists():
        return []
    return sorted(path for path in folder.iterdir() if path.is_file())


@pytest.fixture()
def alice(web):
    browser = web.test_client()
    register_and_login(browser, "alice")
    return web, browser


# ---------------------------------------------------- 1. perjalanan lengkap


def test_the_storage_pages_exist_in_the_real_app(web):
    rules = {rule.rule for rule in web.url_map.iter_rules()}
    assert "/storage/upload" in rules, (
        "create_app() tidak mendaftarkan storage_bp: fitur unggah tidak "
        "bisa dipakai di aplikasi sungguhan"
    )


def test_full_user_journey(alice):
    web, browser = alice
    data = pdf_bytes()

    response = upload(browser, "document", "Laporan Akhir.pdf", data)
    assert response.status_code == 201
    file_id = response.json["id"]
    assert len(storage_files(web)) == 3  # AES, DES, RC4

    listing = browser.get("/storage/").json["items"]
    assert [item["id"] for item in listing] == [file_id]
    assert listing[0]["name"] == "Laporan_Akhir.pdf"
    assert listing[0]["size"] == len(data)

    for algorithm in ("AES", "DES", "RC4"):
        download = browser.get(f"/storage/{file_id}/download/{algorithm}")
        assert download.status_code == 200
        assert download.data == data
        assert "Laporan_Akhir.pdf" in download.headers["Content-Disposition"]
        assert download.headers["Cache-Control"] == "no-store"

    assert post(browser, f"/storage/{file_id}/delete").status_code == 204
    assert browser.get("/storage/").json["items"] == []
    assert browser.get(f"/storage/{file_id}/download/AES").status_code == 404
    assert storage_files(web) == [], "ciphertext tertinggal di disk"


def test_after_logout_files_are_no_longer_reachable(alice):
    web, browser = alice
    file_id = upload(browser, "document", "a.pdf", pdf_bytes()).json["id"]
    assert post(browser, "/auth/logout").status_code == 302
    response = browser.get(f"/storage/{file_id}/download/AES")
    assert response.status_code in (302, 401)
    assert response.data != pdf_bytes()


# ------------------------------------------------------ 2. format realistis


@pytest.mark.parametrize("case", list(FORMATS))
def test_every_supported_format_round_trips(alice, case):
    _, browser = alice
    kind, filename, make = FORMATS[case]
    data = make()
    response = upload(browser, kind, filename, data)
    assert response.status_code == 201, response.json
    file_id = response.json["id"]
    for algorithm in ("AES", "DES", "RC4"):
        assert browser.get(f"/storage/{file_id}/download/{algorithm}").data == data


def test_phone_jpeg_with_extra_data_after_the_end_marker_is_accepted(alice):
    """Banyak ponsel (mis. Motion Photo Samsung, foto HDR) menyimpan data
    tambahan SETELAH penanda akhir JPEG (FF D9). Foto KTP dari ponsel seperti
    itu tetap JPEG yang sah dan harus bisa diunggah."""
    _, browser = alice
    data = jpeg_bytes() + b"MotionPhoto_Data" + mp4_bytes(os.urandom(256))
    response = upload(browser, "id_card", "ktp.jpg", data)
    assert response.status_code == 201, response.json


def test_a_fake_file_with_a_good_extension_is_refused(alice):
    _, browser = alice
    response = upload(browser, "document", "virus.pdf", b"MZ\x90\x00" + os.urandom(64))
    assert response.status_code == 400


# ---------------------------------------------- 3. isi biner & batas blok


@pytest.mark.parametrize("size", [1, 7, 8, 9, 15, 16, 17, 1023, 65_539])
def test_binary_content_is_byte_exact_for_every_algorithm(alice, size):
    _, browser = alice
    # Banyak \n dan \r: menangkap terjemahan newline (masalah khas Windows).
    body = (b"\r\n\n\r\x00\x1a" * (size // 6 + 1))[:size]
    data = mp4_bytes(body)
    file_id = upload(browser, "video", "klip.mp4", data).json["id"]
    for algorithm in ("AES", "DES", "RC4"):
        assert browser.get(f"/storage/{file_id}/download/{algorithm}").data == data


# ------------------------------------------- 4. plaintext tidak bocor


def test_plaintext_never_reaches_the_disk_or_the_database(tmp_path):
    marker = b"RAHASIA-NIK-3578012345678901"
    config = TestingConfig()
    config.SQLALCHEMY_DATABASE_URI = "sqlite:///" + str(tmp_path / "leak.db")
    config.STORAGE_DIR = tmp_path / "store"
    flask_app = create_app(config)
    init_db(flask_app)
    try:
        browser = flask_app.test_client()
        register_and_login(browser, "alice")
        document = b"%PDF-1.4\n" + marker * 50 + b"\n%%EOF\n"
        response = upload(browser, "document", "a.pdf", document)
        assert response.status_code == 201
        for path in storage_files(flask_app):
            assert marker not in path.read_bytes()
    finally:
        with flask_app.app_context():
            db.session.remove()
            db.engine.dispose()
    raw = (tmp_path / "leak.db").read_bytes()
    assert marker not in raw
    assert config.MASTER_KEY not in raw


def test_the_same_file_twice_gives_different_ciphertexts(alice):
    web, browser = alice
    upload(browser, "document", "a.pdf", pdf_bytes())
    upload(browser, "document", "a.pdf", pdf_bytes())
    contents = [path.read_bytes() for path in storage_files(web)]
    assert len(contents) == 6
    assert len(set(contents)) == 6  # kunci & IV acak tiap salinan


# ------------------------------------------------------- 5. restart aplikasi


def make_file_app(tmp_path, master_key=None, secret_key=None):
    config = TestingConfig()
    config.SQLALCHEMY_DATABASE_URI = "sqlite:///" + str(tmp_path / "app.db")
    config.STORAGE_DIR = tmp_path / "store"
    if master_key is not None:
        config.MASTER_KEY = master_key
    if secret_key is not None:
        config.SECRET_KEY = secret_key
    return create_app(config)


def close(flask_app):
    with flask_app.app_context():
        db.session.remove()
        db.engine.dispose()


def test_files_are_still_readable_after_a_restart(tmp_path):
    first = make_file_app(tmp_path)
    init_db(first)
    browser = first.test_client()
    register_and_login(browser, "alice")
    data = pdf_bytes()
    file_id = upload(browser, "document", "a.pdf", data).json["id"]
    close(first)

    second = make_file_app(
        tmp_path,
        master_key=first.config["MASTER_KEY"],
        secret_key=first.config["SECRET_KEY"],
    )
    try:
        browser = second.test_client()
        response = post(
            browser, "/auth/login", data={"username": "alice", "password": PASSWORD}
        )
        assert response.status_code == 302
        for algorithm in ("AES", "DES", "RC4"):
            download = browser.get(f"/storage/{file_id}/download/{algorithm}")
            assert download.status_code == 200
            assert download.data == data
    finally:
        close(second)


def test_a_wrong_master_key_gives_a_clean_error_not_a_crash(tmp_path):
    first = make_file_app(tmp_path)
    init_db(first)
    browser = first.test_client()
    register_and_login(browser, "alice")
    file_id = upload(browser, "document", "a.pdf", pdf_bytes()).json["id"]
    close(first)

    second = make_file_app(tmp_path, master_key=os.urandom(32))
    try:
        browser = second.test_client()
        post(browser, "/auth/login", data={"username": "alice", "password": PASSWORD})
        response = browser.get(f"/storage/{file_id}/download/AES")
        assert response.status_code == 422
        assert b"%PDF" not in response.data
    finally:
        close(second)


def test_an_old_database_without_the_hash_column_is_refused_clearly(tmp_path):
    """instance/app.db yang dibuat sebelum kolom plaintext_sha256 ada harus
    ditolak init_db dengan pesan jelas, bukan crash saat unggah pertama."""
    old = sqlite3.connect(tmp_path / "app.db")
    old.executescript(
        'CREATE TABLE "user" (id INTEGER PRIMARY KEY, username VARCHAR(32) NOT NULL,'
        " password_hash VARCHAR(255) NOT NULL, created_at DATETIME NOT NULL);"
        "CREATE TABLE stored_file (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL,"
        " kind VARCHAR(16) NOT NULL, original_filename VARCHAR(255) NOT NULL,"
        " content_type VARCHAR(100) NOT NULL, plaintext_size INTEGER NOT NULL,"
        " created_at DATETIME NOT NULL);"
    )
    old.close()
    flask_app = make_file_app(tmp_path)
    try:
        with pytest.raises(Exception, match="different columns"):
            init_db(flask_app)
    finally:
        close(flask_app)


# ------------------------------------------------- 6. batas ukuran unggahan


def test_the_file_limit_follows_max_upload_mb(tmp_path):
    """MAX_UPLOAD_MB di .env harus benar-benar mengatur batas file. Dengan
    MAX_UPLOAD_MB=60, file 55 MB tidak boleh ditolak oleh batas 50 MB yang
    tertanam di kode."""
    config = TestingConfig()
    config.STORAGE_DIR = tmp_path / "store"
    config.MAX_CONTENT_LENGTH = 60 * 1024 * 1024
    flask_app = create_app(config)
    data = mp4_bytes(b"\x00" * (55 * 1024 * 1024))
    try:
        with flask_app.test_request_context():
            upload_file = _FileStorage(data, "besar.mp4")
            plaintext, _, _ = validation.validate_upload(upload_file, "video")
            assert len(plaintext) == len(data)
    finally:
        close(flask_app)


def test_an_oversized_request_is_answered_as_json_like_other_storage_errors(
    alice,
):
    """Semua error storage berbentuk JSON {"error": ...}; klien (frontend)
    tidak boleh tiba-tiba menerima halaman HTML untuk kasus 'terlalu besar'."""
    web, browser = alice
    web.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    response = upload(browser, "video", "klip.mp4", mp4_bytes(b"\x00" * 128 * 1024))
    assert response.status_code == 413
    assert response.is_json and "error" in response.json


class _FileStorage:
    def __init__(self, data, filename):
        self.stream = io.BytesIO(data)
        self.filename = filename
