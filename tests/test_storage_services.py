import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest
from flask_login import login_user
from sqlalchemy import func, select
from werkzeug.datastructures import FileStorage

from app.crypto import CryptoError
from app.extensions import db
from app.models import StoredFile
from app.storage import disk, services, validation


@pytest.fixture()
def personal_payload():
    return dict(nama="Contoh", nik="0123456789012345", alamat="Alamat", tanggal_lahir="2000-01-01")


@pytest.fixture()
def stored(app, make_user, personal_payload):
    user = make_user()
    with app.test_request_context('/'):
        login_user(user)
        yield services.create_record(
            plaintext=validation.serialize_personal(personal_payload),
            kind='personal_data', filename='personal-data.json', content_type='application/json',
        )


def paths(app):
    return set(Path(app.config['STORAGE_DIR']).glob('*'))


@pytest.mark.parametrize('algorithm', ['AES', 'DES', 'RC4'])
def test_round_trip(stored, algorithm, personal_payload):
    plain = validation.serialize_personal(personal_payload)
    assert len(stored.copies) == 3
    assert stored.plaintext_sha256 == hashlib.sha256(plain).hexdigest()
    assert services.decrypt_record(stored, algorithm) == plain
    assert all(disk.read_ciphertext(c.storage_name) != plain for c in stored.copies)


def test_update(stored, app, personal_payload):
    old_id, old_paths = stored.id, paths(app)
    personal_payload['nama'] = 'Baru'
    services.update_personal_record(stored, personal_payload)
    assert stored.id == old_id
    assert not old_paths & paths(app)
    assert len(paths(app)) == 3
    for algorithm in ['AES', 'DES', 'RC4']:
        assert json.loads(services.decrypt_record(stored, algorithm)) == personal_payload


def test_delete(stored, app):
    record_id = stored.id
    services.delete_record(stored)
    assert db.session.get(StoredFile, record_id) is None
    assert not paths(app)


@pytest.mark.parametrize('failure', ['hash', 'ciphertext', 'missing'])
def test_integrity_failure(stored, failure):
    copy = next(c for c in stored.copies if c.algorithm == 'AES')
    if failure == 'hash':
        stored.plaintext_sha256 = '0' * 64
        expected = ValueError
    elif failure == 'ciphertext':
        path = disk.storage_path(copy.storage_name)
        body = path.read_bytes()
        path.write_bytes(bytes([body[0] ^ 1]) + body[1:])
        expected = CryptoError
    else:
        disk.remove_ciphertext(copy.storage_name)
        expected = FileNotFoundError
    with pytest.raises(expected):
        services.decrypt_record(stored, 'AES')


@pytest.mark.parametrize('operation', ['create', 'update'])
@pytest.mark.parametrize('failure', ['write', 'commit'])
def test_transaction_failure(stored, app, personal_payload, monkeypatch, operation, failure):
    old_paths = paths(app)
    old_plain = services.decrypt_record(stored, 'AES')
    original_write = services.write_ciphertext
    calls = 0

    def broken_write(data):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError('write failed')
        return original_write(data)

    def broken_commit():
        raise RuntimeError('commit failed')

    monkeypatch.setattr(services, 'write_ciphertext', broken_write if failure == 'write' else original_write)
    if failure == 'commit':
        monkeypatch.setattr(db.session, 'commit', broken_commit)
    with pytest.raises((OSError, RuntimeError)):
        if operation == 'create':
            services.create_record(plaintext=b'new', kind='document', filename='a.pdf', content_type='application/pdf')
        else:
            services.update_personal_record(stored, dict(personal_payload, nama='Baru'))
    assert paths(app) == old_paths
    assert db.session.scalar(select(func.count()).select_from(StoredFile)) == 1
    assert services.decrypt_record(stored, 'AES') == old_plain


def test_cleanup_failure_does_not_mask_error(stored, app, monkeypatch, caplog):
    original = services.write_ciphertext
    calls = 0

    def broken_write(data):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError('original failure')
        return original(data)

    def broken_remove(name):
        raise OSError('cleanup failed')

    monkeypatch.setattr(services, 'write_ciphertext', broken_write)
    monkeypatch.setattr(services, 'remove_ciphertext', broken_remove)
    with pytest.raises(RuntimeError, match='original failure'):
        services.create_record(plaintext=b'new', kind='document', filename='a.pdf', content_type='application/pdf')
    assert 'Cleanup ciphertext gagal' in caplog.text


def test_failed_delete_keeps_files(stored, app, monkeypatch):
    old_paths = paths(app)

    def broken_commit():
        raise RuntimeError('commit failed')

    monkeypatch.setattr(db.session, 'commit', broken_commit)
    with pytest.raises(RuntimeError):
        services.delete_record(stored)
    assert paths(app) == old_paths
    assert db.session.get(StoredFile, stored.id) is not None


@pytest.mark.parametrize('name', ['../escape', '/tmp/escape', '', 'a' * 65])
def test_path_rejected(app, name):
    with pytest.raises(ValueError):
        disk.storage_path(name)


def test_collision_and_missing_delete(app, monkeypatch):
    name = 'a' * 32
    monkeypatch.setattr(disk.secrets, 'token_hex', lambda count: name)
    assert disk.write_ciphertext(b'original') == name
    with pytest.raises(RuntimeError):
        disk.write_ciphertext(b'replacement')
    assert disk.read_ciphertext(name) == b'original'
    disk.remove_ciphertext(name)
    disk.remove_ciphertext(name)


def test_partial_write_cleanup(app, monkeypatch):
    class BrokenWriter:
        def __init__(self, fd):
            self.fd = fd
        def __enter__(self):
            return self
        def write(self, data):
            import os
            os.write(self.fd, data[:1])
            raise OSError('partial write')
        def __exit__(self, *args):
            import os
            os.close(self.fd)
    monkeypatch.setattr(disk.os, 'fdopen', lambda fd, mode: BrokenWriter(fd))
    with pytest.raises(OSError, match='partial write'):
        disk.write_ciphertext(b'abc')
    assert not paths(app)


@pytest.mark.parametrize('payload', [None, {}, {'nama': 12}])
def test_invalid_personal(payload):
    with pytest.raises(validation.ValidationError):
        validation.serialize_personal(payload)


def test_upload_size_and_format(monkeypatch):
    data = b'%PDF-1.4\n%%EOF'
    monkeypatch.setattr(validation, 'MAX_FILE_BYTES', len(data))
    def upload(body):
        return FileStorage(stream=io.BytesIO(body), filename='../../sample.pdf')
    assert validation.validate_upload(upload(data), 'document')[:2] == (data, 'sample.pdf')
    with pytest.raises(validation.UploadTooLarge):
        validation.validate_upload(upload(data + b'x'), 'document')
    with pytest.raises(validation.ValidationError):
        validation.validate_upload(upload(b'invalid'), 'document')


@pytest.mark.parametrize('limit', ['entries', 'size'])
def test_zip_limits_before_decompression(monkeypatch, limit):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('[Content_Types].xml', '<Types/>')
        archive.writestr('word/document.xml', '<document>' + 'a' * 1000 + '</document>')
    monkeypatch.setattr(validation, 'MAX_ZIP_ENTRIES', 1 if limit == 'entries' else 2048)
    monkeypatch.setattr(validation, 'MAX_ZIP_UNCOMPRESSED_BYTES', 10 if limit == 'size' else 100000)
    def no_testzip(self):
        pytest.fail('decompressed archive before checking limits')
    monkeypatch.setattr(zipfile.ZipFile, 'testzip', no_testzip)
    with pytest.raises(validation.ValidationError, match='batas'):
        validation.detect_content_type(buf.getvalue(), 'docx')
