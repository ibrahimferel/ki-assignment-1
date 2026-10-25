# Memakai login dan otorisasi di rute Anda

Panduan singkat untuk anggota yang membuat rute upload, download, daftar dan
hapus. Semua contoh di bawah sudah dicoba pada rute sintetis di app uji.

## Aturan

1. Setiap rute memakai `@login_required`. Satu-satunya rute publik adalah
   `/`, `/auth/login`, `/auth/register` dan file static.
2. Saat membuat data, `owner_id` selalu `current_user.id`. Jangan pernah
   menerima `owner_id` dari form atau JSON.
3. Untuk satu data (lihat, unduh, hapus) pakai `get_owned_or_404`. Untuk
   halaman daftar pakai `owned_select`. Jangan memakai `db.session.get` atau
   filter buatan sendiri.
4. Data milik orang lain dijawab 404, sama persis dengan data yang tidak ada.
   Jangan membuat 403, dan jangan menaruh id atau nama berkas di pesan galat.
5. `CipherCopy` tidak punya pemilik sendiri. Ambil lewat `stored.copies`
   setelah `get_owned_or_404(StoredFile, file_id)`, jangan pernah dari id di
   URL.

## Contoh

```python
from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required
from sqlalchemy.orm import selectinload

from app.authz import get_owned_or_404, owned_select
from app.extensions import db
from app.models import StoredFile

files_bp = Blueprint("files", __name__, url_prefix="/files")


@files_bp.get("/")
@login_required
def list_files():
    rows = db.session.execute(owned_select(StoredFile)).scalars()
    return jsonify(names=[row.original_filename for row in rows])


@files_bp.get("/<int:file_id>")
@login_required
def show_file(file_id):
    stored = get_owned_or_404(
        StoredFile, file_id, options=(selectinload(StoredFile.copies),)
    )
    return jsonify(
        name=stored.original_filename,
        copies=[copy.algorithm for copy in stored.copies],
    )


@files_bp.post("/")
@login_required
def create_file():
    stored = StoredFile(
        owner_id=current_user.id,
        kind="document",
        original_filename=request.form["name"],
        content_type="text/plain",
        plaintext_size=1,
    )
    db.session.add(stored)
    db.session.commit()
    return jsonify(id=stored.id), 201


@files_bp.post("/<int:file_id>/delete")
@login_required
def delete_file(file_id):
    stored = get_owned_or_404(StoredFile, file_id)
    db.session.delete(stored)
    db.session.commit()
    return jsonify(deleted=file_id)
```

Daftarkan blueprint di `create_app` dengan `app.register_blueprint(files_bp)`.

## Token CSRF

Setiap POST, PUT, PATCH dan DELETE tanpa token dijawab 400.

Di form HTML:

```html
<form method="post" action="/files/">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input type="text" name="name">
  <button type="submit">Kirim</button>
</form>
```

Di `fetch`, kirim token di header `X-CSRFToken`. Ambil tokennya dari halaman,
misalnya dari `<meta name="csrf-token" content="{{ csrf_token() }}">`:

```javascript
const token = document.querySelector('meta[name="csrf-token"]').content;
fetch("/files/", {
  method: "POST",
  headers: { "X-CSRFToken": token },
  body: new URLSearchParams({ name: "laporan.pdf" }),
});
```

Token berlaku 3600 detik. Berhenti sesudah logout, jadi ambil token baru dari
halaman setelah login ulang.

## Unggah berkas

Form HTML butuh `enctype="multipart/form-data"`, dan token CSRF dikirim
sebagai field tersembunyi:

```html
<form method="post" action="/files/upload" enctype="multipart/form-data">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input type="file" name="file" required>
  <button type="submit">Unggah</button>
</form>
```

Untuk `fetch` dengan `FormData`, token dikirim di header `X-CSRFToken`, dan
`Content-Type` **tidak diisi manual**: browser menambahkannya sendiri beserta
`boundary`. Bila Anda mengisinya, `boundary` hilang dan unggahan gagal.

```javascript
const token = document.querySelector('meta[name="csrf-token"]').content;
const data = new FormData();
data.append("file", fileInput.files[0]);
fetch("/files/upload", {
  method: "POST",
  headers: { "X-CSRFToken": token },
  body: data,
});
```

Sisi server (contoh ini hanya menghitung ukuran; enkripsi dan penyimpanan
adalah tugas modul masing-masing). Tambahkan ke blueprint di atas:

```python
@files_bp.post("/upload")
@login_required
def upload_file():
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify(error="Pilih satu berkas."), 400
    return jsonify(size=len(uploaded.read())), 201
```

Hal yang perlu diketahui:

- **Batas ukuran:** `MAX_UPLOAD_MB` di `.env` (bawaan 50, artinya
  50 x 1024 x 1024 byte per permintaan). Permintaan yang lebih besar dijawab
  413. Batas ini berlaku untuk seluruh isi permintaan, bukan per berkas.
- **Penyimpanan:** setiap berkas disimpan sebagai tiga salinan sandi (AES,
  DES, RC4), jadi kebutuhan penyimpanan sekitar tiga kali ukuran berkas.
- **Log:** jangan mencatat password, kunci (`SECRET_KEY`, `MASTER_KEY`, kunci
  per berkas), token sesi atau cookie, token CSRF, maupun isi berkas.
  Catatan bawaan server hanya memuat metode, alamat dan status permintaan.

## Berkas di disk

Path hanya dibuat dari `storage_name` di database, sesudah
`get_owned_or_404`, dan tidak pernah dari nama berkas pengguna. Perbandingan
path harus memakai `resolve()` dan `is_relative_to`:

```python
base = current_app.config["STORAGE_DIR"].resolve()
path = (base / copy.storage_name).resolve()
if not path.is_relative_to(base):
    abort(404)
```

Menghapus `StoredFile` menghapus baris `cipher_copy` lewat cascade database,
tetapi **tidak** menghapus berkas ciphertext di disk. Urutannya: periksa
pemilik, catat semua `storage_name`, hapus baris dan `commit`, baru hapus
berkas (jika gagal, catat dan lanjutkan). Berkas yang hilang saat diunduh
(`FileNotFoundError`) dijawab 404.

## Header keamanan dan CSP

Setiap jawaban (halaman, pengalihan, error 4xx/5xx, dan berkas statis) diberi
header ini oleh `app/security_headers.py`. Rute tidak perlu menambahkannya,
dan tidak bisa melemahkannya:

| Header | Nilai |
| --- | --- |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=(), usb=()` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Content-Security-Policy` | `default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'` |
| `Cache-Control` | `no-store` (dipaksa; bukan untuk `/static/`) |
| `Strict-Transport-Security` | `max-age=31536000`, hanya bila `SESSION_COOKIE_SECURE` aktif |

Hanya CSP yang **bawaan**: rute boleh menggantinya dengan nilai yang lebih
ketat (misalnya menambah `sandbox`), tetapi tidak boleh melonggarkannya. Kode
tidak bisa membedakan keduanya, jadi larangan ini hanya ada di dokumen ini.

**Cache.** Semua jawaban selain `/static/` selalu `Cache-Control: no-store`.
Rute tidak bisa memilih cache sendiri: `private, max-age=60`, `public`, ETag,
dan `no-cache` bawaan `send_file` semuanya ditimpa. Kode yang mengirim data
pengguna tidak perlu mengatur apa pun.

**Akibat CSP: CSS dan JavaScript harus berupa berkas di `app/static`**, dan
dipanggil dengan `url_for('static', ...)`. Yang diblokir browser: `<script>`
dan `<style>` di dalam halaman, atribut `style=`, atribut `onclick=` dan
sejenisnya, URL `javascript:`, serta sumber dari situs lain (CDN, font).

```html
<link rel="stylesheet" href="{{ url_for('static', filename='css/app.css') }}">
<script src="{{ url_for('static', filename='js/files.js') }}"></script>
```

Menghubungkan tombol dilakukan dari berkas JS, bukan dari atribut HTML:

```javascript
document.querySelector("#upload-button").addEventListener("click", send);
```

**Pratinjau gambar dan video.** Sumber `blob:` dan `data:` ikut diblokir.
Sajikan pratinjau lewat rute biasa, misalnya
`<img src="/files/1/view" alt="">` atau `<video src="/files/2/view"
controls>`, bukan `blob:` atau `data:`: sumber yang sama dengan situs ini
sudah diizinkan oleh `'self'`. Rute itu tetap memakai `get_owned_or_404`. Bila memang butuh `blob:`
(misalnya untuk hasil dekripsi di browser), minta persetujuan dulu: yang
ditambah hanya `img-src 'self' blob:` atau `media-src 'self' blob:`, bukan
`default-src`.

`tests/test_security_headers.py` memeriksa semua templat di
`app/templates` dan akan gagal bila ada skrip atau gaya inline, atribut
`on...=`, URL `javascript:`, atau sumber dari situs lain.

**Daftar periksa manual di browser.** Efek CSP tidak bisa diuji di tes
otomatis. Sudah dicoba di Safari 26.2: header lengkap di Network, skrip
inline yang disuntik lewat Console ditolak, halaman login tanpa pelanggaran.
Chrome dan Firefox: BLOCKED sampai dicoba.

1. Jalankan `python run.py`, buka `http://127.0.0.1:5000/auth/login`, lalu
   buka DevTools (Console dan Network).
2. Console tidak boleh berisi pesan `Refused to ...` (CSP) pada
   `/auth/login`, `/auth/register` dan `/`.
3. Di Network, klik permintaan halaman: semua header di tabel di atas ada,
   kecuali `Strict-Transport-Security` (tidak ada di http).
4. Coba bingkai: simpan `<iframe src="http://127.0.0.1:5000/">` di berkas
   lokal dan buka; browser harus menolak menampilkannya.
5. Di Console halaman login jalankan
   `document.body.insertAdjacentHTML("beforeend", '<img src=x onerror="alert(1)">')`:
   handler tidak boleh jalan dan Console menampilkan `Refused to execute
   inline event handler`.

## Tes yang akan gagal

`tests/test_security_inventory.py` memeriksa semua rute di `app.url_map`:

- rute di luar daftar publik yang bisa dipakai tanpa login membuat
  `test_every_route_outside_the_public_list_needs_a_login` gagal;
- POST/PUT/PATCH/DELETE yang tidak menolak permintaan tanpa token CSRF
  membuat `test_every_unsafe_route_refuses_a_missing_or_wrong_token` gagal;
- converter URL selain `string`, `path`, `int`, `float` dan `uuid` membuat
  tes gagal dengan pesan yang jelas (tambahkan nilai contohnya di
  `SAMPLE_VALUES`).

## Menguji rute Anda

Pakai dua pengguna dan satu data milik pengguna pertama. Pengguna kedua harus
mendapat 404 yang isi dan headernya sama dengan id yang tidak ada. Contoh
lengkap ada di `tests/test_authz.py`.

## Yang perlu diketahui

- Id pengguna dan berkas yang dihapus dapat dipakai ulang (SQLite tanpa
  autoincrement). Tinjau ulang bila fitur hapus akun ditambahkan.
- CSP memakai `setdefault`, jadi rute secara teknis bisa melonggarkannya;
  larangannya hanya ada di dokumen ini.
- Header `Server` dari server pengembangan membuka versi Werkzeug dan
  Python. Itu bukan kendali aplikasi; tutup dengan server produksi di depan.
- Efek CSP baru dicoba manual di satu browser (Safari 26.2). Chrome dan
  Firefox belum.
