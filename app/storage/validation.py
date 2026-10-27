import io
import json
import re
import zipfile
from datetime import date

from flask import current_app, has_app_context
from werkzeug.utils import secure_filename

DEFAULT_MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_FILE_BYTES = None
MAX_PERSONAL_BYTES = 16 * 1024
MAX_ZIP_ENTRIES = 2048
MAX_ZIP_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
PERSONAL_FIELDS = {"nama", "nik", "alamat", "tanggal_lahir"}
UPLOAD_FORMATS = {
    "id_card": {"jpg", "jpeg", "png"},
    "document": {"pdf", "doc", "docx", "xls", "xlsx"},
    "video": {"mp4"},
}


class ValidationError(ValueError):
    """Input tidak valid; boleh dipetakan menjadi HTTP 400."""
    pass

class UploadTooLarge(ValidationError):
    """Ukuran melampaui batas; petakan menjadi HTTP 413."""

def max_file_bytes():
    if MAX_FILE_BYTES is not None:
        return MAX_FILE_BYTES
    if has_app_context():
        config = current_app.config.get("MAX_CONTENT_LENGTH")
        if config:
            return config
    return DEFAULT_MAX_FILE_BYTES

def detect_content_type(data, extension):
    """Return MIME setelah memeriksa format konten, bukan MIME browser."""
    extension = extension.lower()
    if extension in {"jpg", "jpeg"}:
        if not (data.startswith(b"\xff\xd8\xff")
                and b"\xff\xd9" in data[3:]):
            raise ValidationError("File gambar tidak valid")
        return "image/jpeg"
    elif extension == "png":
        if not (data.startswith(b"\x89PNG\r\n\x1a\n")
                and b"IEND\xaeB`\x82" in data[8:]):
            raise ValidationError("File gambar tidak valid")
        return "image/png"
    elif extension == "pdf":
        if not (data.startswith(b"%PDF-") and b"%%EOF" in data[-1024:]):
            raise ValidationError("File PDF tidak valid")
        return "application/pdf"
    elif extension in {"doc", "xls"}:
        if not data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            raise ValidationError("File OLE (DOC/XLS) tidak valid")
        # Nama stream OLE disimpan dalam UTF-16LE.
        if extension == "doc":
            names = ["WordDocument"]
        else:
            names = ["Workbook", "Book"]
        if not any(n.encode("utf-16-le") in data for n in names):
            raise ValidationError("File OLE (DOC/XLS) tidak valid")
        if extension == "doc":
            return "application/msword"
        return "application/vnd.ms-excel"
    elif extension in {"docx", "xlsx"}:
        if not data.startswith(b"PK\x03\x04"):
            raise ValidationError("File ZIP Office (DOCX/XLSX) tidak valid")
        main = "word/document.xml" if extension == "docx" else "xl/workbook.xml"
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                entries = zf.infolist()
                if (len(entries) > MAX_ZIP_ENTRIES
                        or sum(entry.file_size for entry in entries) > MAX_ZIP_UNCOMPRESSED_BYTES):
                    raise ValidationError("Arsip Office melampaui batas pemeriksaan")
                if any(entry.flag_bits & 1 for entry in entries):
                    raise ValidationError("Arsip Office terenkripsi tidak didukung")
                names = set(zf.namelist())
                if "[Content_Types].xml" not in names or main not in names:
                    raise ValidationError("File ZIP Office (DOCX/XLSX) tidak valid")
                if zf.testzip() is not None:
                    raise ValidationError("File ZIP Office (DOCX/XLSX) tidak valid")
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError) as exc:
            raise ValidationError("File ZIP Office (DOCX/XLSX) tidak valid") from exc
        if extension == "docx":
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    elif extension == "mp4":
        if not (len(data) > 12 and data[4:8] == b"ftyp"):
            raise ValidationError("File MP4 tidak valid")
        return "video/mp4"
    else:
        raise ValidationError("Format file tidak valid")


def validate_upload(uploaded, kind):
    """Return (plaintext: bytes, safe_filename: str, content_type: str)."""
    if uploaded is None or not getattr(uploaded, "filename", None):
        raise ValidationError("File tidak ditemukan")
    if kind not in UPLOAD_FORMATS:
        raise ValidationError("Jenis unggahan tidak valid")

    safe_filename = secure_filename(uploaded.filename)
    if not safe_filename or len(safe_filename) > 255 or "." not in safe_filename:
        raise ValidationError("Nama file tidak valid")

    extension = safe_filename.rsplit(".", 1)[1].lower()
    if extension not in UPLOAD_FORMATS[kind]:
        raise ValidationError("Ekstensi file tidak diizinkan")
    
    limit = max_file_bytes()
    plaintext = uploaded.stream.read(limit + 1)
    if not plaintext:
        raise ValidationError("File kosong")
    if len(plaintext) > limit:
        raise UploadTooLarge("Ukuran file melebihi batas")

    # Jangan percaya uploaded.content_type; tentukan dari isi file.
    content_type = detect_content_type(plaintext, extension)
    return plaintext, safe_filename, content_type


def serialize_personal(payload):
    """Return JSON UTF-8 bytes dengan field yang sudah dibersihkan."""
    if not isinstance(payload, dict):
        raise ValidationError("Data pribadi harus berupa objek")
    if set(payload.keys()) != PERSONAL_FIELDS:
        raise ValidationError("Field data pribadi tidak sesuai")
    if not all(isinstance(v, str) for v in payload.values()):
        raise ValidationError("Semua field harus string")

    nama = payload["nama"].strip()
    nik = payload["nik"].strip()
    alamat = payload["alamat"].strip()
    tanggal_lahir = payload["tanggal_lahir"].strip()

    if not 1 <= len(nama) <= 100:
        raise ValidationError("Nama harus 1..100 karakter")
    if not re.fullmatch(r"[0-9]{16}", nik):
        raise ValidationError("NIK harus 16 digit")
    if not 1 <= len(alamat) <= 1000:
        raise ValidationError("Alamat harus 1..1000 karakter")
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", tanggal_lahir):
        raise ValidationError("Format tanggal_lahir harus YYYY-MM-DD")
    try:
        lahir = date.fromisoformat(tanggal_lahir)
    except ValueError as exc:
        raise ValidationError("tanggal_lahir tidak valid") from exc
    if lahir > date.today():
        raise ValidationError("tanggal_lahir tidak boleh di masa depan")

    clean = {
        "nama": nama,
        "nik": nik,
        "alamat": alamat,
        "tanggal_lahir": tanggal_lahir,
    }
    result = json.dumps(clean, ensure_ascii=False, sort_keys=True).encode("utf-8")
    if len(result) > MAX_PERSONAL_BYTES:
        raise ValidationError("Data pribadi terlalu besar")
    return result
