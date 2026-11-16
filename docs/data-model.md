# Model Data (CP2) - Rencana dan Penjelasan

Status: semua tabel (`user`, `stored_file`, `cipher_copy`, `user_key`,
`access_request`, `shared_copy`), `PRAGMA foreign_keys`, `init_db.py`,
autentikasi, helper kepemilikan (`app/authz.py`), modul enkripsi
(`app/crypto/`), serta layanan unggah/unduh/hapus dan penyimpanan ciphertext
(`app/storage/`) **sudah diimplementasikan dan diuji** di branch ini. Bagian
5, 7 dan 8 menjelaskan perilaku kode yang ada. Yang belum ada: kode yang
membuat permintaan akses dan `shared_copy` (alur berbagi, lihat
`docs/sharing-design.md`). Cara memakai bagian yang sudah ada: lihat
`docs/auth-integration.md`.

Tabel Assignment 2 (`user_key`, `access_request`, `shared_copy`) dan
kontraknya ada di `docs/sharing-design.md`; dokumen ini tetap membahas tiga
tabel Assignment 1.

Penulis: Anggota 1 (Backend, Autentikasi, dan Basis Data).
Dibaca oleh: Anggota 2 (kriptografi) dan Anggota 3 (penyimpanan/unggah).

## 1. Keputusan yang mendasari

Dua keputusan kelompok sudah diambil (lihat dokumen keputusan CP2).
Dokumen ini menurunkannya menjadi skema.

| # | Keputusan | Pilihan |
| --- | --- | --- |
| 1 | Tafsir "semua algoritma" | **C**: setiap data disimpan sebagai tiga salinan ciphertext (AES, DES, RC4), relasi 1-ke-N |
| 1b | Salinan yang diunduh | Pengguna memilih salinan; **default AES** |
| 2 | Pengelolaan kunci | **K3**: kunci acak per salinan, dibungkus master key di `.env` yang terpisah dari `SECRET_KEY` |
| 3 | Folder ciphertext | `instance/storage/` (sudah tercakup `instance/` di `.gitignore`) |
| 4 | `MAX_UPLOAD_MB` | **50** (bawaan di `app/config.py` dan `.env.example`; bagian 9) |

## 2. Gambaran entitas

```
user 1 ------< stored_file 1 ------< cipher_copy
(akun)         (satu data milik       (satu salinan ciphertext
                satu pengguna)         per algoritma, tepat 3)
```

- Satu pengguna punya banyak data.
- Satu data punya tepat tiga salinan (AES, DES, RC4).
- Database hanya menyimpan metadata dan kunci dalam bentuk terlindungi: kunci
  salinan dibungkus master key, kolom private key di `user_key` memuat
  private key yang dienkripsi dengan password pengguna (akun lama mendapat
  key saat login berikutnya yang berhasil), dan kunci publik memang publik. Tidak ada kunci
  mentah.
  **Isi data (plaintext maupun ciphertext) tidak disimpan di database.**
  Ciphertext disimpan sebagai file di `instance/storage/`.

### 2.1 Data pribadi (teks) dan jenis data

Data pribadi berupa teks (nama, alamat, dan sebagainya), foto KTP, dokumen
PDF/DOC/XLS, dan video diperlakukan **seragam** sebagai "data" di tabel
`stored_file`, dibedakan oleh kolom `kind`. Teks data pribadi diserialisasi
menjadi satu blob lalu dienkripsi lewat jalur yang sama dengan file.

Alasan: satu jalur kode berarti satu tempat untuk diuji dan satu aturan
akses. Konsekuensinya data pribadi juga menjadi tiga salinan. Alternatif
(tabel kolom terenkripsi terpisah) ada di bagian 13 (keputusan nomor 1).

Nilai `kind` (daftar tertutup): `personal_data`, `id_card`, `document`,
`video`.

## 3. Tabel `user`

| Kolom | Tipe | Aturan |
| --- | --- | --- |
| `id` | integer, PK | otomatis |
| `username` | string(32) | unik, NOT NULL; disimpan huruf kecil (lihat 3.1) |
| `password_hash` | string(255) | NOT NULL; hanya hash, tidak pernah password |
| `created_at` | datetime (UTC) | NOT NULL, diisi aplikasi |

Tidak ada kolom kunci di `user`; pasangan kunci pengguna ada di tabel
terpisah `user_key` (lihat `docs/sharing-design.md`). Untuk data Assignment 1
(K3), kunci tidak bergantung pada password, sehingga ganti atau lupa password
tidak membuat data itu hilang. Pengecualian: private key di
`user_key` dienkripsi dengan password pengguna, jadi lupa password berarti
private key itu tidak bisa dibuka lagi (belum ada fitur ganti atau reset
password). Akun lama mendapat key saat login berikutnya yang berhasil; kalau
pembuatannya gagal, pengguna tetap masuk tanpa baris `user_key` dan dicoba lagi
di login berikutnya.

### 3.1 Catatan username dan password

- Username dinormalisasi ke huruf kecil sebelum disimpan dan dicari, supaya
  "Budi" dan "budi" tidak menjadi dua akun. Aturan karakter dan panjang
  ditetapkan di `app/auth/services.py`: 3 sampai 32 karakter ASCII
  (`a-z`, `0-9`, `.`, `_`, `-`), diawali dan diakhiri huruf atau angka.
- Sandi 10 sampai 128 karakter (dinormalisasi NFKC). Hash memakai **Argon2id**
  lewat `argon2-cffi` (parameter bawaan pustaka), bukan fungsi hash Werkzeug.

## 4. Tabel `stored_file`

Satu baris = satu data milik satu pengguna.

| Kolom | Tipe | Aturan |
| --- | --- | --- |
| `id` | integer, PK | otomatis |
| `owner_id` | integer, FK ke `user.id` | NOT NULL, indeks; ON DELETE CASCADE |
| `kind` | string(16) | NOT NULL; salah satu nilai di 2.1 |
| `original_filename` | string(255) | NOT NULL; hanya untuk tampilan dan nama unduhan |
| `content_type` | string(100) | NOT NULL; yang diklaim klien, **tidak dipercaya** |
| `plaintext_size` | integer | NOT NULL; ukuran asli dalam byte |
| `plaintext_sha256` | string(64) | NOT NULL; SHA-256 plaintext (heksadesimal), dipakai untuk memastikan hasil dekripsi benar |
| `created_at` | datetime (UTC) | NOT NULL |

Catatan:

- `original_filename` **tidak pernah dipakai sebagai nama file di disk**
  (mencegah path traversal). Saat unduh, nama ini dibersihkan dulu.
- `original_filename`, `kind`, dan `plaintext_size` tersimpan sebagai
  plaintext di database. Ini bocor ke siapa pun yang membaca database dan
  dicatat sebagai keterbatasan (bagian 10).
- Tidak ada kolom `algorithm` atau kunci di sini; semuanya ada di
  `cipher_copy`.

## 5. Tabel `cipher_copy`

Satu baris = satu salinan ciphertext dari satu data.

| Kolom | Tipe | Aturan |
| --- | --- | --- |
| `id` | integer, PK | otomatis |
| `file_id` | integer, FK ke `stored_file.id` | NOT NULL, indeks; ON DELETE CASCADE |
| `algorithm` | string(8) | NOT NULL; `AES`, `DES`, atau `RC4` |
| `mode` | string(8) | NULL untuk RC4; mode non-ECB untuk AES dan DES |
| `iv` | blob | NULL untuk RC4; IV/nonce untuk AES dan DES |
| `wrapped_key` | blob | NOT NULL; kunci salinan ini, sudah dibungkus master key |
| `storage_name` | string(64) | NOT NULL, unik; nama file acak di `instance/storage/` |
| `ciphertext_size` | integer | NOT NULL; ukuran file ciphertext dalam byte |
| `encrypt_seconds` | float | NOT NULL; waktu enkripsi salinan ini, untuk analisis performa |

Batasan tabel: `UNIQUE (file_id, algorithm)` agar satu data tidak punya dua
salinan AES.

Catatan:

- **Kunci acak per salinan** (bukan satu kunci per data yang diturunkan
  lagi). Alasan: tidak perlu fungsi penurunan kunci; panjang kunci tiap
  algoritma mengikuti kebutuhannya sendiri (AES-256 32 byte, DES 8 byte,
  RC4 16 byte); kunci satu salinan tidak membuka salinan lain. Harga: tiga operasi pembungkusan per unggah, yang diabaikan
  dibanding enkripsi file.
- Isi `wrapped_key` (dibuat `app/crypto/keys.py`), berurutan: 1 byte versi
  (nilai 1), nonce 16 byte, tag GCM 16 byte, lalu ciphertext AES-256-GCM
  dengan master key (32 byte) sebagai kunci. Yang dibungkus adalah kunci
  cipher disambung kunci MAC: kunci cipher 32 byte untuk AES, 8 byte untuk
  DES, 16 byte untuk RC4; kunci MAC selalu 32 byte. AAD GCM = label
  `cryptoapp|keywrap` disambung nama algoritma, sehingga `wrapped_key` satu
  salinan tidak bisa dibuka sebagai salinan algoritma lain. Master key yang
  salah atau data rusak terdeteksi saat dibuka. Dari sisi database ia hanya
  blob.
- `mode` dan `iv` dicatat per salinan: AES dan DES memakai CBC (padding
  PKCS#7), jadi `mode` = `CBC` dan `iv` terisi; RC4 tidak punya mode dan iv
  (keduanya NULL).
- `encrypt_seconds` dicatat saat unggah sehingga satu unggahan sudah
  menghasilkan data perbandingan tiga algoritma. Waktu dekripsi tidak
  disimpan; diukur oleh skrip benchmark, bukan oleh aplikasi.
- `ciphertext_size` dicatat karena padding (AES dan DES) dan tag HMAC-SHA256
  32 byte membuat ciphertext lebih besar dari `plaintext_size`; ukuran ini
  sudah termasuk tag. Selisihnya bagian dari analisis.

## 6. Aturan dan jaminan (invarian)

| # | Aturan | Ditegakkan oleh | Diuji di |
| --- | --- | --- | --- |
| I1 | Setiap `stored_file` punya tepat tiga `cipher_copy` (AES, DES, RC4) | `create_record` di `app/storage/services.py` (satu transaksi) | `tests/test_storage_services.py::test_round_trip` |
| I2 | Tidak ada `stored_file` setengah jadi: salah satu enkripsi gagal berarti seluruh unggahan dibatalkan | `create_record` di `app/storage/services.py` | `tests/test_storage_services.py::test_transaction_failure` |
| I3 | `UNIQUE (file_id, algorithm)` dan `UNIQUE (storage_name)` | database | `tests/test_models.py` |
| I4 | Hapus pengguna atau data menghapus baris turunannya | database (FK cascade) | `tests/test_models.py` |
| I5 | Setiap akses data lewat `owner_id` pengguna yang login | `app/authz.py` (`get_owned_or_404`, `owned_select`) | `tests/test_authz.py`, `tests/test_security_inventory.py` |
| I6 | Kunci tidak pernah ditulis ke log, pesan galat, atau database dalam bentuk mentah | semua | sebagian: tes sapuan rahasia di respons dan log (`tests/test_security_inventory.py`); kunci per salinan dibuat `app/crypto/keys.py` dan hanya disimpan terbungkus (`wrapped_key`); `tests/test_real_world.py::test_plaintext_never_reaches_the_disk_or_the_database` memastikan plaintext dan `MASTER_KEY` tidak ada di file ciphertext maupun database |

**Peringatan SQLite (penting untuk I3 dan I4):** SQLite mengabaikan foreign
key dan cascade kecuali `PRAGMA foreign_keys=ON` dijalankan pada **setiap
koneksi**. Flask-SQLAlchemy tidak melakukannya otomatis. Sudah diterapkan:
pendengar peristiwa koneksi di `app/db_pragmas.py`, dengan tes di
`tests/test_models.py` yang membuktikan baris turunan benar-benar terhapus
dan gagal bila pragma dimatikan.

## 7. Penyimpanan ciphertext

- Lokasi: `instance/storage/`, satu file per `cipher_copy`, bernama
  `storage_name` (string acak, bukan dari masukan pengguna).
- Pembuat folder: **perintah inisialisasi basis data (`init_db.py`)**,
  idempoten, izin `0700` (folder lama yang lebih longgar diperketat).
  `write_ciphertext` (`app/storage/disk.py`) juga membuat folder bila belum
  ada (izin `0700`), jadi folder yang hilang dibuat ulang saat file ditulis.
- Lokasi diatur lewat konfigurasi (`STORAGE_DIR`); `TestingConfig` memakai
  folder sementara yang unik per instance dan dihapus setelah tes.
- Urutan tulis saat unggah (`create_record`): enkripsi di memori, tulis tiga
  file ke disk dan tambahkan baris, lalu satu commit; jika gagal, rollback
  dan file yang sudah ditulis dihapus. Saat hapus atau ganti data pribadi
  (`delete_record`, `update_personal_record`): commit database dulu, baru
  file lama dihapus. Kegagalan menghapus file dicatat sebagai peringatan
  (hanya nama acak) dan menyisakan file yatim (ada di disk, tidak di
  database) yang tidak berbahaya; baris tanpa file tidak boleh terjadi.

## 8. Alur

### 8.1 Unggah (`POST /storage/upload`, `POST /storage/personal`)

1. Pengguna login; rute unggah memeriksa sesi (`@login_required`, lihat `docs/auth-integration.md`).
2. `validate_upload` (`app/storage/validation.py`) membersihkan nama file
   (`secure_filename`), memeriksa ekstensi menurut `kind` dan batas
   `MAX_UPLOAD_MB`, dan menentukan tipe isi dari isi file, bukan dari klaim
   klien. Teks data pribadi diserialisasi menjadi satu blob.
3. `create_record` (`app/storage/services.py`) menghitung SHA-256 plaintext
   dan memanggil `encrypt_all` (`app/crypto/engine.py`): tiga kunci cipher
   acak dan tiga kunci MAC, tiga enkripsi (CBC untuk AES dan DES, RC4 tanpa
   mode) dengan tag HMAC-SHA256, waktu tiap enkripsi dicatat, dan tiap
   pasangan kunci dibungkus dengan master key.
4. Layanan menulis tiga file ke folder penyimpanan (`STORAGE_DIR`, bawaan
   `instance/storage/`).
5. Layanan membuat satu `stored_file` dan tiga `cipher_copy` dalam **satu
   transaksi**. Gagal di mana pun berarti semuanya dibatalkan (I2).

### 8.2 Unduh (`GET /storage/<id>/download/<algorithm>`)

1. Pengguna memilih data dan algoritma, yang ada di path rute. Tautan
   unduh di halaman utama memakai AES (`app/static/js/storage.js`); nilai
   selain `AES`/`DES`/`RC4` dijawab 404.
2. Layanan mencari data berdasarkan `id` **dan** `owner_id` pengguna (I5).
   Data milik orang lain dijawab 404, sama seperti data yang tidak ada, agar
   keberadaannya tidak bocor. Sudah diterapkan oleh `get_owned_or_404` di
   `app/authz.py`; jawaban 404 yang identik dibuktikan oleh `tests/test_authz.py`.
3. `decrypt_record` membuka `wrapped_key` dengan master key, membaca file,
   memverifikasi tag HMAC, mendekripsi, lalu memeriksa SHA-256 plaintext.
   File hilang dijawab 404; ciphertext yang diubah atau rusak dijawab 422.
4. Hasil dikirim dengan nama berkas yang sudah dibersihkan dengan
   `secure_filename` saat unggah.

## 9. Konfigurasi baru dan `MAX_UPLOAD_MB`

Perubahan ini sudah diterapkan di `app/config.py` dan `.env.example`:

| Variabel | Aturan |
| --- | --- |
| `MASTER_KEY` | wajib; heksadesimal 64 karakter (32 byte); tidak boleh sama dengan `SECRET_KEY`; gagal start jika salah (gaya `ConfigError`) |
| `STORAGE_DIR` | opsional; default `instance/storage` |
| `MAX_UPLOAD_MB` | bawaan 50 (alasan di bawah); harus bilangan bulat lebih dari 0 |

Seperti `SECRET_KEY`, validasi `MASTER_KEY` hanya memeriksa format dan
panjang, bukan keacakan.

### 9.1 Kenapa 50, bukan 100

`MAX_CONTENT_LENGTH` berlaku untuk **seluruh isi satu permintaan**, jadi
jika formulir mengirim KTP, dokumen, dan video sekaligus, jumlahnya harus
muat. Dengan pilihan C, satu unggahan sebesar N membutuhkan:

| N (MB) | Disk (3 salinan, 3N) | Memori puncak jika satu salinan diproses bergantian (2N) | Memori puncak jika tiga salinan ditahan sekaligus (4N) |
| --- | --- | --- | --- |
| 50 | 150 MB | 100 MB | 200 MB |
| 100 | 300 MB | 200 MB | 400 MB |

Ini **hitungan, bukan pengukuran**. Padding dan overhead tidak dihitung, dan
server pengembangan melayani beberapa permintaan bersamaan, sehingga
puncak bisa berlipat.

Alasan memilih 50:

- Video demo pendek yang terkompresi umumnya muat; 50 MB memberi ruang
  untuk bahan uji tanpa membuat satu unggahan menahan ratusan MB.
- Untuk laporan, ukuran uji yang bermakna (misalnya 1, 10, 40 MB) tetap
  terjangkau.
- Angka mudah dinaikkan karena berasal dari `.env`. Jika video demo kelompok
  lebih besar, naikkan ke 100 **setelah** benchmark Anggota 2 mengukur memori
  dan waktu nyata.
- Berkas uji sebaiknya ≤ 40 MB agar ada sisa untuk overhead multipart dan
  kolom formulir lain.

Nilai 50 sudah dipakai di `DEFAULT_MAX_UPLOAD_MB` (`app/config.py`) dan di
`.env.example`. Mengubahnya berarti mengubah kedua tempat itu dan tes di
`tests/test_config.py` bersama-sama. Catatan: form `/auth/*` punya batas
sendiri yang lebih kecil, 16 KiB (lihat `docs/auth-integration.md`).

## 10. Keterbatasan (untuk laporan)

- Dengan K3, siapa pun yang memegang `.env` dan database dapat membuka semua
  data. Enkripsi di sini melindungi data saat tersimpan, bukan dari
  administrator server.
- Hilangnya `MASTER_KEY` berarti semua data tidak dapat dibuka. Cadangan dan
  penanggung jawabnya harus ditetapkan kelompok.
- DES (56 bit efektif) dan RC4 tidak dianggap aman; keduanya dipakai karena
  diminta soal. **Konsekuensi pilihan C:** ketiga salinan berisi plaintext
  yang sama, sehingga kerahasiaan sebuah data hanya sekuat salinan
  terlemahnya. Penyerang yang berhasil membuka salinan DES atau RC4 membaca
  data yang sama dengan salinan AES. Menambahkan AES tidak memperkuat data
  yang juga disimpan dalam DES dan RC4. Ini wajib dinyatakan jujur di
  laporan.
- CBC (AES/DES) dan RC4 tidak otentik dengan sendirinya, tetapi aplikasi
  menambahkan tag HMAC-SHA256 (encrypt-then-MAC) pada tiap ciphertext dan
  memeriksa SHA-256 plaintext, sehingga perubahan ciphertext terdeteksi
  saat dekripsi (`tests/test_crypto.py::test_tampered_ciphertext_is_detected`).
- Metadata (`original_filename`, `kind`, ukuran, waktu) tersimpan plaintext.
- Tiga salinan memakan sekitar tiga kali ruang disk dan waktu enkripsi.
- Validasi `MASTER_KEY` memeriksa format dan panjang, bukan keacakan.
- Skema dibuat lewat `create_all()` tanpa migrasi. Menambah tabel baru tidak
  perlu menghapus apa pun (`init_db.py` hanya membuat tabel yang belum ada,
  seperti saat tiga tabel Assignment 2 ditambahkan). Mengubah kolom tabel
  yang sudah ada berarti menghapus `instance/app.db` dan menginisialisasi
  ulang; data uji hilang.
- `stored_file.plaintext_sha256` menyimpan SHA-256 plaintext tanpa salt di
  database; siapa pun yang memegang database dapat mencocokkan tebakan atas
  data yang entropinya rendah (misalnya NIK).
- Database yang dibuat sebelum kolom itu ada ditolak oleh `init_db.py` dengan
  galat "Table 'stored_file' already exists with different columns"
  (`tests/test_real_world.py::test_an_old_database_without_the_hash_column_is_refused_clearly`);
  `instance/app.db` harus dihapus lalu diinisialisasi ulang.
- Id bilangan bulat berurutan dapat ditebak; perlindungannya adalah
  pemeriksaan `owner_id` (I5), bukan kerahasiaan id.
- Id pengguna dan berkas yang dihapus dapat dipakai ulang (SQLite tanpa
  autoincrement); tinjau ulang bila fitur hapus akun ditambahkan.
- Keterbatasan keamanan HTTP (pembatas percobaan, sesi, CSP, ukuran body):
  lihat bagian Keterbatasan di `README.md`.

## 11. Gaya model dan hal teknis

- Gaya model yang dipakai: **`db.Column` klasik** untuk seluruh tim. Alasan: lebih
  sedikit jebakan tipe pada Python 3.9 (tidak ada sintaks `X | None`) dan
  lebih mudah dibaca pemula. Flask-SQLAlchemy 3.1.1 mendukung keduanya.
- Waktu disimpan sebagai UTC, naive di SQLite (SQLite tidak menyimpan zona).
- Nama tabel eksplisit (`user`, `stored_file`, `cipher_copy`), tidak
  mengandalkan penamaan otomatis.

## 12. Dampak ke anggota lain

| Anggota | Yang perlu diketahui / disediakan |
| --- | --- |
| Anggota 2 | Menyediakan (sudah ada di `app/crypto/`): enkripsi satu blob menjadi tiga hasil (algoritma, mode, iv, kunci terbungkus, ciphertext, waktu) dan kebalikannya untuk satu salinan. Mode CBC untuk AES dan DES, RC4 tanpa mode; format `wrapped_key` ada di bagian 5. PyCryptodome ada di `requirements.txt`. File diproses utuh di memori dan ketiga salinan ditahan sekaligus (kolom 4N di 9.1). |
| Anggota 3 | Menyediakan (sudah ada di `app/storage/`): rute `/storage/`, pemilihan algoritma saat unduh, pembersihan nama berkas, validasi `kind` dan ukuran. Folder penyimpanan dibuat `init_db.py` dan dipastikan ada oleh `write_ciphertext`. Tidak menyimpan apa pun di luar folder penyimpanan (`STORAGE_DIR`). |
| Anggota 1 | Sudah ada: model, `init_db.py` (membuat tabel dan folder), pendengar pragma FK, `app/authz.py` (`get_owned_or_404`, `owned_select`: pencarian yang selalu menyaring `owner_id`), konfigurasi `MASTER_KEY`, `STORAGE_DIR` dan `MAX_UPLOAD_MB`, autentikasi. Dari Assignment 2: tabel berbagi, helper sisi requester (`get_requested_or_404`, `requested_select`), key pair saat register dan login pertama akun lama, fixture bersama untuk tes. |

## 13. Keputusan yang diambil (dulu pertanyaan terbuka)

| # | Pertanyaan | Keputusan | Bukti di repo |
| --- | --- | --- | --- |
| 1 | Data pribadi teks | Seragam sebagai `stored_file` dengan `kind=personal_data` | `KINDS` di `app/models.py` |
| 2 | Kunci per salinan atau per data | Per salinan (`wrapped_key` di `cipher_copy`); kuncinya dibuat `generate_key` | `app/models.py`, `app/crypto/keys.py` |
| 3 | `MAX_UPLOAD_MB` | 50 | `app/config.py`, `.env.example` |
| 4 | 404 untuk data milik orang lain | Ya | `app/authz.py`, `tests/test_authz.py` |
| 5 | Gaya model | `db.Column` | `app/models.py` |
| 6 | `encrypt_seconds` di database | Ya, kolom di `cipher_copy` | `app/models.py` |
| 7 | `.gitignore` tanpa `*.db` | `*.db` ditambahkan | `.gitignore` |

## 14. Status pekerjaan

| Bagian | Status | Berkas utama |
| --- | --- | --- |
| Konfigurasi dan validasi `.env` | selesai, diuji | `app/config.py`, `tests/test_config.py` |
| Model data dan pragma FK | selesai, diuji | `app/models.py`, `app/db_pragmas.py`, `tests/test_models.py` |
| Inisialisasi database dan folder penyimpanan | selesai, diuji | `init_db.py`, `app/database.py`, `tests/test_init_db.py` |
| Autentikasi, sesi, CSRF, pembatas percobaan | selesai, diuji | `app/auth/`, `tests/test_auth*.py` |
| Otorisasi kepemilikan data | selesai, diuji | `app/authz.py`, `tests/test_authz.py` |
| Header keamanan, CSP, batas body `/auth/*` | selesai, diuji | `app/security_headers.py`, `app/request_limits.py` |
| Modul enkripsi AES/DES/RC4 | selesai, diuji | `app/crypto/`, `tests/test_crypto.py` |
| Unggah, unduh, hapus, penyimpanan ciphertext | selesai, diuji | `app/storage/`, `tests/test_storage_*.py` |
| Benchmark performa | skrip dan data ada; analisis di laporan belum ditulis | `tests/test_crypto_performance.py`, `crypto_benchmark.csv`, rute `/storage/<id>/comparison` |
| Tabel berbagi dan helper sisi requester | selesai, diuji | `app/models.py`, `app/authz.py`, `tests/test_models.py`, `tests/test_authz.py` |
| Key pair saat register dan login pertama akun lama | selesai, diuji | `app/auth/services.py`, `app/crypto/asymmetric.py`, `tests/test_register_keys.py`, `tests/test_login_key.py`, `tests/test_user_keypair.py` |
| Fixture bersama untuk tes berbagi | selesai, diuji | `tests/sharing_fixtures.py`, `tests/test_sharing_fixtures.py`, `tests/test_sharing_storage.py` |
| Permintaan akses dan salinan berbagi (rute, halaman, kriptografi) | belum ada | lihat `docs/sharing-design.md` |
