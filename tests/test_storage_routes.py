"""HTTP storage tests with real login, CSRF and independent clients."""
import io
import re

import pytest
from argon2 import PasswordHasher
from sqlalchemy import select

from app.auth import services as auth_services
from app.extensions import db
from app.models import StoredFile
from app.storage import validation
from app.storage.disk import storage_path

PASSWORD = 'correct horse battery'
PAYLOAD = dict(nama='Contoh', nik='0123456789012345', alamat='Alamat', tanggal_lahir='2000-01-01')


@pytest.fixture()
def storage_app(web):
    """Use the same registered storage routes as the application."""
    return web


def csrf_token(client):
    for path in ['/auth/login', '/']:
        page = client.get(path).get_data(as_text=True)
        found = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page)
        if found is not None:
            return found[1]
    raise AssertionError('CSRF token missing from rendered pages')


def post(client, path, **kwargs):
    headers = kwargs.pop('headers', {})
    headers['X-CSRFToken'] = csrf_token(client)
    return client.post(path, headers=headers, **kwargs)


@pytest.fixture()
def storage_web(storage_app, monkeypatch):
    web = storage_app
    monkeypatch.setattr(auth_services, '_HASHER', PasswordHasher(time_cost=1, memory_cost=8, parallelism=1))
    monkeypatch.setattr(auth_services, '_dummy', None)
    with web.app_context():
        auth_services.register_user('alice', PASSWORD)
        auth_services.register_user('bobby', PASSWORD)
    clients = [web.test_client(), web.test_client()]
    for client, username in zip(clients, ['alice', 'bobby']):
        response = post(client, '/auth/login', data=dict(username=username, password=PASSWORD))
        assert response.status_code == 302
        assert client.get('/storage/').status_code == 200
    return web, *clients


@pytest.mark.parametrize('algorithm', ['AES', 'DES', 'RC4'])
def test_upload_and_download_identical(storage_web, algorithm):
    web, alice, _ = storage_web
    data = b'%PDF-1.4\n%%EOF'
    response = post(alice, '/storage/upload', data={'kind': 'document', 'file': (io.BytesIO(data), 'sample.pdf')})
    assert response.status_code == 201
    record_id = response.json['id']
    with web.app_context():
        assert len(db.session.get(StoredFile, record_id).copies) == 3
    response = alice.get(f'/storage/{record_id}/download/{algorithm}')
    assert response.status_code == 200
    assert response.data == data
    assert response.headers['Cache-Control'] == 'no-store'


def test_personal_crud(storage_web):
    web, alice, _ = storage_web
    response = post(alice, '/storage/personal', json=PAYLOAD)
    assert response.status_code == 201
    record_id = response.json['id']
    assert alice.get(f'/storage/{record_id}/personal').json == PAYLOAD
    with web.app_context():
        old_paths = [storage_path(c.storage_name) for c in db.session.get(StoredFile, record_id).copies]
    changed = dict(PAYLOAD, nama='Baru')
    assert post(alice, f'/storage/{record_id}/personal/update', json=changed).status_code == 200
    assert alice.get(f'/storage/{record_id}/personal').json == changed
    assert all(not path.exists() for path in old_paths)
    with web.app_context():
        new_paths = [storage_path(c.storage_name) for c in db.session.get(StoredFile, record_id).copies]
    assert post(alice, f'/storage/{record_id}/delete').status_code == 204
    assert all(not path.exists() for path in new_paths)
    assert alice.get(f'/storage/{record_id}/personal').status_code == 404


@pytest.mark.parametrize('operation', ['personal', 'download/AES', 'comparison', 'personal/update', 'delete'])
def test_other_user_cannot_access_owned_object(storage_web, operation):
    _, alice, bobby = storage_web
    record_id = post(alice, '/storage/personal', json=PAYLOAD).json['id']
    url = f'/storage/{record_id}/{operation}'
    missing = f'/storage/999999/{operation}'
    if operation in {'personal/update', 'delete'}:
        response = post(bobby, url, json=PAYLOAD)
        absent = post(bobby, missing, json=PAYLOAD)
    else:
        response, absent = bobby.get(url), bobby.get(missing)
    assert response.status_code == absent.status_code == 404
    assert response.data == absent.data
    assert alice.get(f'/storage/{record_id}/personal').json == PAYLOAD


def test_list_is_private(storage_web):
    _, alice, bobby = storage_web
    ids = [post(c, '/storage/personal', json=PAYLOAD).json['id'] for c in [alice, bobby]]
    for client, record_id in zip([alice, bobby], ids):
        assert [item['id'] for item in client.get('/storage/').json['items']] == [record_id]


def test_comparison_returns_only_owned_persisted_measurements(storage_web):
    web, alice, _ = storage_web
    content = b'%PDF-1.4\n%%EOF'
    record_id = post(alice, '/storage/upload', data={
        'kind': 'document', 'file': (io.BytesIO(content), 'sample.pdf'),
    }).json['id']
    response = alice.get(f'/storage/{record_id}/comparison')
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.json['original_size'] == len(content)
    with web.app_context():
        copies = db.session.get(StoredFile, record_id).copies
        expected = {c.algorithm: (c.mode, c.encrypt_seconds, c.ciphertext_size) for c in copies}
    assert {c['algorithm'] for c in response.json['copies']} == {'AES', 'DES', 'RC4'}
    for copy in response.json['copies']:
        assert set(copy) == {'algorithm', 'mode', 'encryption_seconds', 'encrypted_size'}
        assert (copy['mode'], copy['encryption_seconds'], copy['encrypted_size']) == expected[copy['algorithm']]


def test_anonymous_requires_login(storage_app):
    client = storage_app.test_client()
    assert client.get('/storage/').status_code == 302
    assert post(client, '/storage/personal', json=PAYLOAD).status_code == 302


@pytest.mark.parametrize('token', [None, 'wrong'])
def test_mutations_require_csrf(storage_web, token):
    web, alice, _ = storage_web
    record_id = post(alice, '/storage/personal', json=PAYLOAD).json['id']
    for url in ['/storage/upload', '/storage/personal', f'/storage/{record_id}/personal/update', f'/storage/{record_id}/delete']:
        headers = {} if token is None else {'X-CSRFToken': token}
        assert alice.post(url, json=PAYLOAD, headers=headers).status_code == 400
    with web.app_context():
        assert len(db.session.scalars(select(StoredFile)).all()) == 1
    assert alice.get(f'/storage/{record_id}/personal').json == PAYLOAD


def test_invalid_input_and_size(storage_web, monkeypatch):
    _, alice, _ = storage_web
    assert post(alice, '/storage/personal', json={}).status_code == 400
    assert post(alice, '/storage/upload', data={'kind': 'document', 'file': (io.BytesIO(b'bad'), 'a.pdf')}).status_code == 400
    monkeypatch.setattr(validation, 'MAX_FILE_BYTES', 10)
    assert post(alice, '/storage/upload', data={'kind': 'document', 'file': (io.BytesIO(b'x' * 11), 'a.pdf')}).status_code == 413


@pytest.mark.parametrize('failure', ['missing', 'hash', 'tag'])
def test_download_errors(storage_web, failure):
    web, alice, _ = storage_web
    record_id = post(alice, '/storage/personal', json=PAYLOAD).json['id']
    with web.app_context():
        stored = db.session.get(StoredFile, record_id)
        copy = next(c for c in stored.copies if c.algorithm == 'AES')
        path = storage_path(copy.storage_name)
        if failure == 'missing':
            path.unlink()
        elif failure == 'hash':
            stored.plaintext_sha256 = '0' * 64
            db.session.commit()
        else:
            data = path.read_bytes()
            path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
    assert alice.get(f'/storage/{record_id}/download/AES').status_code == (404 if failure == 'missing' else 422)
