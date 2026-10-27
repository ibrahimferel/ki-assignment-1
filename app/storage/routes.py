import json
from io import BytesIO

from flask import Blueprint, abort, jsonify, request, send_file
from flask_login import login_required

from app.authz import get_owned_or_404, owned_select
from app.crypto import CryptoError
from app.extensions import db
from app.models import StoredFile
from app.storage.services import (
    create_record, decrypt_record, delete_record, update_personal_record,
)
from app.storage.validation import (
    UploadTooLarge, ValidationError, serialize_personal, validate_upload,
)

storage_bp = Blueprint("storage", __name__, url_prefix="/storage")


@storage_bp.errorhandler(ValidationError)
def validation_error(error):
    return jsonify(error=str(error)), 400


@storage_bp.errorhandler(UploadTooLarge)
def upload_too_large(error):
    return jsonify(error="Ukuran file melebihi batas"), 413


@storage_bp.get("/")
@login_required
def index():
    rows = db.session.execute(
        owned_select(StoredFile).order_by(StoredFile.id.desc())
    ).scalars()
    items = [
        {
            "id": f.id,
            "name": f.original_filename,
            "kind": f.kind,
            "size": f.plaintext_size,
        }
        for f in rows
    ]
    return jsonify(items=items)


@storage_bp.post("/upload")
@login_required
def upload():
    uploaded = request.files.get("file")
    kind = request.form.get("kind")
    plaintext, filename, content_type = validate_upload(uploaded, kind)
    stored = create_record(
        plaintext=plaintext,
        kind=kind,
        filename=filename,
        content_type=content_type,
    )
    return jsonify(id=stored.id), 201


@storage_bp.get("/<int:file_id>/download/<algorithm>")
@login_required
def download(file_id, algorithm):
    stored = get_owned_or_404(StoredFile, file_id)
    if algorithm not in {c.algorithm for c in stored.copies}:
        abort(404)
    try:
        plaintext = decrypt_record(stored, algorithm)
    except FileNotFoundError:
        abort(404)
    except (CryptoError, ValueError):
        return jsonify(error="Data tidak dapat didekripsi"), 422
    return send_file(
        BytesIO(plaintext),
        as_attachment=True,
        download_name=stored.original_filename,
        mimetype="application/octet-stream",
    )


@storage_bp.get("/<int:file_id>/comparison")
@login_required
def comparison(file_id):
    stored = get_owned_or_404(StoredFile, file_id)
    return jsonify(
        original_size=stored.plaintext_size,
        copies=[
            {
                "algorithm": copy.algorithm,
                "mode": copy.mode,
                "encryption_seconds": copy.encrypt_seconds,
                "encrypted_size": copy.ciphertext_size,
            }
            for copy in stored.copies
        ],
    )


@storage_bp.post("/personal")
@login_required
def create_personal():
    plaintext = serialize_personal(request.get_json(silent=True))
    stored = create_record(
        plaintext=plaintext,
        kind="personal_data",
        filename="personal-data.json",
        content_type="application/json",
    )
    return jsonify(id=stored.id), 201


@storage_bp.get("/<int:file_id>/personal")
@login_required
def show_personal(file_id):
    stored = get_owned_or_404(StoredFile, file_id)
    if stored.kind != "personal_data":
        abort(404)
    try:
        plaintext = decrypt_record(stored, "AES")
        payload = json.loads(plaintext)
    except FileNotFoundError:
        abort(404)
    except (CryptoError, ValueError):
        return jsonify(error="Data tidak dapat dibaca"), 422
    return jsonify(payload)


@storage_bp.post("/<int:file_id>/personal/update")
@login_required
def update_personal(file_id):
    stored = get_owned_or_404(StoredFile, file_id)
    if stored.kind != "personal_data":
        abort(404)
    update_personal_record(stored, request.get_json(silent=True))
    return jsonify(id=stored.id), 200


@storage_bp.post("/<int:file_id>/delete")
@login_required
def delete(file_id):
    stored = get_owned_or_404(StoredFile, file_id)
    delete_record(stored)
    return "", 204
