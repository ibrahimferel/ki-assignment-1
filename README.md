# Tugas Kriptografi 1: bagian inti (autentikasi, basis data, otorisasi)

Aplikasi web Flask + SQLite + SQLAlchemy yang dirancang untuk menyimpan data
pribadi, gambar KTP, dokumen (PDF/DOC/XLS) dan video dalam bentuk terenkripsi
(AES, DES, RC4). Branch ini (`feature/core-auth`) berisi **bagian inti yang
dikerjakan Anggota 1**: konfigurasi, model data, login dengan kontrol akses
per pengguna, dan lapisan keamanan HTTP.

**Belum ada di branch ini:** modul enkripsi AES/DES/RC4, formulir dan rute
unggah/unduh berkas, serta analisis performa; folder untuk bagian itu belum
ada di repo. Panduan untuk anggota lain ada di `docs/auth-integration.md`.

## Prasyarat

- Python 3.9 (versi yang diuji: 3.9.6 di macOS dan 3.9.25 di Linux; versi lain
  belum diuji).
- `pip` dan modul `venv`.

## Instalasi

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Konfigurasi `.env` dan kunci

Aplikasi menolak start tanpa `SECRET_KEY` dan `MASTER_KEY`. Salin templat,
lalu isi kedua kunci **tanpa menampilkannya di layar**:

```bash
cp .env.example .env
chmod 600 .env
python - <<'PY'
import re
import secrets
from pathlib import Path

path = Path(".env")
text = path.read_text()
for name in ("SECRET_KEY", "MASTER_KEY"):
    text = re.sub(
        rf"^{name}=[ \t]*$",
        lambda match, name=name: f"{name}={secrets.token_hex(32)}",
        text,
        count=1,
        flags=re.MULTILINE,
    )
path.write_text(text)
print("Kunci ditulis ke .env (nilai tidak ditampilkan).")
PY
```

Perintah ini hanya mengisi baris yang masih kosong, jadi aman dijalankan ulang
dan tidak menimpa kunci yang sudah ada. Kedua kunci berbeda satu sama lain.

| Variabel | Arti |
| --- | --- |
| `SECRET_KEY` | wajib; menandatangani cookie sesi dan token CSRF (minimal 32 karakter) |
| `MASTER_KEY` | wajib; 64 karakter heksadesimal (32 byte), harus berbeda dari `SECRET_KEY`; pelindung kunci per berkas |
| `FLASK_DEBUG` | `0` (bawaan) atau `1` hanya di mesin sendiri |
| `SESSION_COOKIE_SECURE` | `1` bila situs disajikan lewat HTTPS; `0` untuk `http://127.0.0.1` |
| `DATABASE_URL` | opsional; bawaan: SQLite di folder `instance/` |
| `STORAGE_DIR` | opsional; bawaan: `instance/storage` |
| `MAX_UPLOAD_MB` | batas satu permintaan unggah, bawaan 50 |

**Jangan commit `.env`** (sudah diabaikan oleh `.gitignore`). Simpan cadangan
`MASTER_KEY` di tempat aman: bila hilang, semua berkas terenkripsi tidak bisa
dibuka lagi.

## Membuat basis data

```bash
python init_db.py
```

Membuat tabel `user`, `stored_file`, `cipher_copy` dan folder penyimpanan.
Aman dijalankan ulang: data yang ada tidak diubah.

## Menjalankan

```bash
python run.py
```

Server pengembangan mendengarkan di `http://127.0.0.1:8000` (hanya mesin ini).
Bila port 8000 terpakai, pilih port lain:

```bash
python run.py --port 8001
```

Port 5000 sengaja bukan bawaan karena di macOS sering dipakai layanan AirPlay
Receiver. Halaman yang tersedia: `/` (halaman sementara), `/auth/register`,
`/auth/login` dan `/auth/logout`.

## Menjalankan tes

```bash
python -m pytest -q
```

`pytest.ini` menjadikan setiap warning sebagai error. Hasil terakhir di
macOS: 958 tes lulus. Pemeriksaan gaya (opsional, tidak ada di
`requirements.txt`): `pip install flake8`, lalu `flake8 app tests`.

## Struktur folder

```
app/
  __init__.py          application factory (create_app), Flask-Login, CSRF, cookie sesi
  config.py            pembacaan dan validasi .env (ConfigError bila salah)
  models.py            User, StoredFile, CipherCopy
  database.py          pembuatan tabel dan folder penyimpanan (init_db)
  db_pragmas.py        PRAGMA foreign_keys di setiap koneksi SQLite
  extensions.py        objek db SQLAlchemy
  authz.py             get_owned_or_404, owned_select (kepemilikan data)
  security_headers.py  header keamanan, CSP, Cache-Control
  request_limits.py    batas body 16 KiB untuk /auth/*
  placeholder.py       halaman sementara "/"
  auth/                services (Argon2id), forms, routes, throttle, redirects
  templates/           base.html, placeholder_home.html, auth/login.html, auth/register.html
docs/
  auth-integration.md  panduan untuk anggota lain (lindungi rute, CSRF, unggah, CSP)
  data-model.md        rancangan dan penjelasan model data
tests/                 tes otomatis (pytest)
init_db.py             membuat tabel dan folder penyimpanan
run.py                 pintu masuk server pengembangan
```

## Ringkasan keamanan (yang sudah ada dan teruji)

- **Sandi:** hash Argon2id (parameter bawaan `argon2-cffi`); panjang 10 sampai
  128 karakter, dinormalisasi NFKC, ditolak bila termasuk sandi umum.
  Nama pengguna 3 sampai 32 karakter ASCII (`a-z`, `0-9`, `.`, `_`, `-`).
- **Login:** pesan gagal sama untuk sandi salah dan nama tidak dikenal;
  `session.clear()` sebelum login (anti fixation); proteksi sesi `strong`.
- **Sesi:** cookie `HttpOnly`, `SameSite=Lax`, `Secure` bila
  `SESSION_COOKIE_SECURE=1`; berlaku 2 jam dan tidak diperpanjang otomatis.
- **CSRF:** diwajibkan untuk semua permintaan yang mengubah data.
- **Pembatas percobaan:** login 5 gagal per pasangan alamat+nama dan 20 per
  alamat dalam 15 menit; registrasi 10 per alamat per jam. Jawaban 429
  dengan `Retry-After`.
- **Header:** `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy`, `Permissions-Policy`, COOP/CORP, CSP ketat (tanpa
  skrip/gaya inline), `Cache-Control: no-store` selain untuk berkas statis,
  HSTS hanya bila cookie `Secure` aktif.
- **Ukuran body:** `/auth/*` dibatasi 16 KiB (413 bila lebih besar); rute lain
  mengikuti `MAX_UPLOAD_MB`.
- **Kontrol akses:** data milik pengguna hanya bisa diakses pemiliknya lewat
  `get_owned_or_404`; milik orang lain dan tidak ada sama-sama 404. Tes
  inventaris memeriksa semua rute di `app.url_map` (harus butuh login dan
  token CSRF).
- **Rahasia:** `.env`, `instance/` dan file `*.db` diabaikan Git; tes
  menyapu respons dan log dari sandi, hash dan kunci.

## Keterbatasan

Penanda: **[T]** terbukti oleh tes otomatis, **[M]** pengamatan manual,
**[K]** keputusan rancangan (dibaca dari kode), **[B]** BLOCKED (belum bisa
diuji).

1. Hitungan pembatas percobaan ada di memori satu proses: hilang saat server
   dihidupkan ulang dan tidak dibagi antar worker. [T]
2. Pembatas hanya membaca `request.remote_addr`, jadi di belakang proxy semua
   klien tampak satu alamat; header `X-Forwarded-For` palsu tidak membantu. [T]
3. Proteksi sesi `strong` Flask-Login memakai `X-Forwarded-For` untuk membentuk
   identitas sesi; ini tidak memengaruhi pembatas. [M]
4. Cookie sesi berlaku 2 jam tanpa diperpanjang, dan logout hanya menghapus
   cookie (tidak ada pencabutan sesi di server). [K]
5. Id pengguna dan berkas yang dihapus dapat dipakai ulang (SQLite tanpa
   autoincrement), sehingga cookie lama bisa terpetakan ke pengguna baru;
   tinjau ulang bila fitur hapus akun ditambahkan. [M]
6. Form di `/auth/*` dibatasi 16 KiB (413 bila lebih besar); rute lain dibatasi
   `MAX_CONTENT_LENGTH` (50 MB bawaan). [T]
7. Body urlencoded tanpa Content-Length (chunked) tidak ditolak, tetapi dipotong
   di batas. Ini diamati di server pengembangan Werkzeug [M]; server produksi
   (gunicorn/nginx) belum diuji [B].
8. Respons 413 tidak dibatasi lajunya (biaya per permintaan kecil karena body
   tidak dibaca); namun 413 tidak dihitung sebagai percobaan login. [K, T]
9. CSP dipasang dengan `setdefault`, jadi rute secara teknis bisa
   melonggarkannya; larangannya hanya ada di dokumen. [K]
10. Header `Server` dari server pengembangan menampilkan versi Werkzeug dan
    Python. [M]
11. Efek CSP baru dicoba manual di Safari 26.2 [M]; Chrome dan Firefox [B].
12. Header HSTS dan cookie `Secure` hanya diuji lewat pengaturan konfigurasi,
    belum lewat koneksi TLS sungguhan. [T, B]
13. Nama pengguna hanya ASCII dan daftar sandi umum berukuran kecil. [T]
14. Aplikasi tidak mencatat log audit (tidak ada log login gagal atau 429). [K]
15. Skema dibuat dengan `create_all()` tanpa migrasi; mengubah skema berarti
    membuat ulang basis data. [K]
16. Rancangan: DES dan RC4 lemah; ketiga salinan berisi plaintext yang sama,
    sehingga kerahasiaan data hanya sekuat salinan terlemah; pemegang `.env`
    dan basis data dapat membuka semua data. Modul enkripsinya belum ada di
    branch ini. [K]
17. Angka mutasi di laporan dijalankan di sandbox oleh asisten AI dan tidak
    direproduksi di macOS. [M]
18. Hanya Python 3.9 yang diuji. [M]

## Pembagian peran

| Anggota | Bagian |
| --- | --- |
| Anggota 1 | Backend, autentikasi, dan basis data (branch ini) |
| Anggota 2 | diisi tim |
| Anggota 3 | diisi tim |
| Anggota 4 | diisi tim |
