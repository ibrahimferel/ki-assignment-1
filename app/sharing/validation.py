from app.auth.services import UsernamePolicyError, normalize_username
from app.authz import MAX_ID
from app.crypto.share import PACKAGE_MAX_CHARS
from app.storage.validation import ValidationError

MAX_REASON_CHARS = 500
MAX_PASSWORD_CHARS = 1024
MAX_FILES_PER_APPROVAL = 100

def _require_object(payload):
    if not isinstance(payload, dict):
        raise ValidationError("Body harus berupa objek JSON")
    return payload

def validate_request_payload(payload):
    data = _require_object(payload)
    username = data.get("username")
    reason = data.get("reason")
    if not isinstance(username, str) or not isinstance(reason, str):
        raise ValidationError("Username dan alasan harus string")
    try:
        username = normalize_username(username)
    except (UsernamePolicyError, TypeError):
        raise ValidationError("Username tidak valid") from None
    reason = reason.strip()
    if not reason:
        raise ValidationError("Alasan tidak boleh kosong")
    if len(reason) > MAX_REASON_CHARS:
        raise ValidationError("Alasan terlalu panjang")
    return username, reason

def validate_approval_payload(payload):
    data = _require_object(payload)
    file_ids = data.get("file_ids")
    if not isinstance(file_ids, list):
        raise ValidationError("file_ids harus berupa list")
    if not file_ids:
        raise ValidationError("file_ids tidak boleh kosong")
    if len(file_ids) > MAX_FILES_PER_APPROVAL:
        raise ValidationError("file_ids terlalu banyak")
    for item in file_ids:
        if type(item) is not int or not 1 <= item <= MAX_ID:
            raise ValidationError("file_ids tidak valid")
    if len(set(file_ids)) != len(file_ids):
        raise ValidationError("file_ids tidak boleh duplikat")
    return file_ids

def validate_unlock_payload(payload):
    data = _require_object(payload)
    package = data.get("key_package")
    password = data.get("password")
    if not isinstance(package, str) or not isinstance(password, str):
        raise ValidationError("key_package dan password harus string")
    if len(package) > PACKAGE_MAX_CHARS or len(password) > MAX_PASSWORD_CHARS:
        raise ValidationError("Input unlock terlalu panjang")
    return package, password