import json
from io import BytesIO

from flask import Blueprint, abort, jsonify, request, send_file
from flask_login import login_required

from app.crypto import CryptoError
from app.sharing import services
from app.sharing.validation import (
    ValidationError,
    validate_approval_payload,
    validate_request_payload,
    validate_unlock_payload,
)
from app.storage.routes import INLINE_CSP, INLINE_TYPES

sharing_bp = Blueprint("sharing", __name__, url_prefix="/sharing")

@sharing_bp.errorhandler(ValidationError)
def validation_error(error):
    return jsonify(error=str(error)), 400

@sharing_bp.errorhandler(services.UnlockThrottled)
def throttled_error(error):
    response = jsonify(error="Terlalu banyak percobaan")
    response.status_code = 429
    response.headers["Retry-After"] = str(error.retry_after)
    return response

@sharing_bp.errorhandler(CryptoError)
@sharing_bp.errorhandler(ValueError)
def unprocessable_error(error):
    return jsonify(error="Data tidak dapat didekripsi"), 422

@sharing_bp.errorhandler(FileNotFoundError)
def missing_ciphertext(error):
    return jsonify(error="Tidak ditemukan"), 404

@sharing_bp.post("/requests")
@login_required
def create_request():
    username, reason = validate_request_payload(request.get_json(silent=True))
    access = services.create_request(username=username, reason=reason)
    return jsonify(id=access.id), 201

@sharing_bp.get("/requests")
@login_required
def list_requests():
    return jsonify(services.list_requests())

@sharing_bp.post("/requests/<int:request_id>/approve")
@login_required
def approve_request(request_id: int):
    file_ids = validate_approval_payload(request.get_json(silent=True))
    package = services.approve_request(request_id, file_ids=file_ids)
    return jsonify(key_package=package)

@sharing_bp.get("/requests/<int:request_id>/key-package")
@login_required
def get_key_package(request_id: int):
    return jsonify(key_package=services.get_key_package(request_id))

@sharing_bp.post("/requests/<int:request_id>/reject")
@login_required
def reject_request(request_id: int):
    services.reject_request(request_id)
    return "", 204

@sharing_bp.post("/requests/<int:request_id>/revoke")
@login_required
def revoke_request(request_id: int):
    services.revoke_request(request_id)
    return "", 204

@sharing_bp.post("/requests/<int:request_id>/unlock")
@login_required
def unlock_request(request_id: int):
    package, password = validate_unlock_payload(request.get_json(silent=True))
    return jsonify(services.unlock_request(
        request_id, key_package=package, password=password,
    ))

@sharing_bp.get("/requests/<int:request_id>/files/<int:file_id>/download")
@login_required
def download(request_id: int, file_id: int):
    stored, plaintext = services.read_shared_file(request_id, file_id)
    return send_file(
        BytesIO(plaintext),
        as_attachment=True,
        download_name=stored.original_filename,
        mimetype="application/octet-stream",
    )

@sharing_bp.get("/requests/<int:request_id>/files/<int:file_id>/view")
@login_required
def view(request_id: int, file_id: int):
    stored, plaintext = services.read_shared_file(request_id, file_id)
    if stored.content_type not in INLINE_TYPES:
        abort(404)
    response = send_file(
        BytesIO(plaintext), mimetype=stored.content_type, as_attachment=False,
    )
    response.headers["Content-Security-Policy"] = INLINE_CSP
    return response

@sharing_bp.get("/requests/<int:request_id>/files/<int:file_id>/personal")
@login_required
def personal(request_id: int, file_id: int):
    stored, plaintext = services.read_shared_file(request_id, file_id)
    if stored.kind != "personal_data":
        abort(404)
    return jsonify(json.loads(plaintext))