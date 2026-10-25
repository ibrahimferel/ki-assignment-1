# Model Data (CP2) - Rencana dan Penjelasan

Status: tabel `user`, `stored_file` dan `cipher_copy`, `PRAGMA foreign_keys`,
`init_db.py`, autentikasi, dan helper kepemilikan (`app/authz.py`) **sudah
diimplementasikan dan diuji** di branch `feature/core-auth`. **Modul
enkripsi, layanan unggah/unduh, dan penyimpanan ciphertext belum ada**: bagian
5 (isi kolom kunci), 7 (urutan tulis), 8.1 di bawah masih rancangan
untuk Anggota 2 dan 3. Cara memakai bagian yang sudah ada: lihat
`docs/auth-integration.md`.

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
- Database hanya menyimpan metadata dan kunci yang sudah dibungkus.
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

Tidak ada kolom kunci di `user`. Itu konsekuensi pilihan K3: kunci tidak
bergantung pada password, sehingga ganti atau lupa password tidak membuat
data hilang.

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
  algoritma mengikuti kebutuhannya sendiri (DES butuh 8 byte, AES 16/24/32
  byte, RC4 panjang bervariasi); kunci satu salinan tidak membuka salinan
  lain. Harga: tiga operasi pembungkusan per unggah, yang diabaikan
  dibanding enkripsi file.
- Format isi `wrapped_key` (algoritma pembungkus, nonce, tag) ditentukan
  Anggota 2. Dari sisi database ia hanya blob. Usulan: pembungkus yang
  terautentikasi, sehingga master key yang salah atau data rusak terdeteksi
  saat dibuka.
- `mode` dan `iv` dicatat per salinan karena Anggota 2 yang memilih mode
  (CBC, CTR, dan seterusnya). Skema tidak mengunci pilihan itu.
- `encrypt_seconds` dicatat saat unggah sehingga satu unggahan sudah
  menghasilkan data perbandingan tiga algoritma. Waktu dekripsi tidak
  disimpan; diukur oleh skrip benchmark, bukan oleh aplikasi.
- `ciphertext_size` dicatat karena mode dengan padding membuat ciphertext
  lebih besar dari `plaintext_size`; selisihnya bagian dari analisis.

## 6. Aturan dan jaminan (invarian)

| # | Aturan | Ditegakkan oleh | Diuji di |
| --- | --- | --- | --- |
| I1 | Setiap `stored_file` punya tepat tiga `cipher_copy` (AES, DES, RC4) | layanan unggah (satu transaksi) | belum: layanan unggah belum ada |
| I2 | Tidak ada `stored_file` setengah jadi: salah satu enkripsi gagal berarti seluruh unggahan dibatalkan | layanan unggah | belum: layanan unggah belum ada |
| I3 | `UNIQUE (file_id, algorithm)` dan `UNIQUE (storage_name)` | database | `tests/test_models.py` |
| I4 | Hapus pengguna atau data menghapus baris turunannya | database (FK cascade) | `tests/test_models.py` |
| I5 | Setiap akses data lewat `owner_id` pengguna yang login | `app/authz.py` (`get_owned_or_404`, `owned_select`) | `tests/test_authz.py`, `tests/test_security_inventory.py` |
| I6 | Kunci tidak pernah ditulis ke log, pesan galat, atau database dalam bentuk mentah | semua | sebagian: tes sapuan rahasia di respons dan log (`tests/test_security_inventory.py`); kunci per berkas belum ada |

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
  idempoten, izin `0700` (folder lama yang lebih longgar diperketat). Kode Anggota 3 mengasumsikan folder sudah ada dan tidak membuatnya
  sendiri di jalur biasa.
- Lokasi diatur lewat konfigurasi (`STORAGE_DIR`); `TestingConfig` memakai
  folder sementara yang unik per instance dan dihapus setelah tes.
- Rancangan (layanan belum ada): urutan tulis saat unggah: tulis semua file ke disk, lalu commit database.
  Jika commit gagal, file yang sudah ditulis dihapus. Sebaliknya saat hapus:
  hapus baris database, lalu file. File yatim (ada di disk, tidak di
  database) tidak berbahaya tetapi dicatat dan diuji; baris tanpa file
  tidak boleh terjadi.

## 8. Alur

### 8.1 Unggah (rancangan; belum diimplementasikan)

1. Pengguna login; rute unggah memeriksa sesi (`@login_required`, lihat `docs/auth-integration.md`).
2. Anggota 3 menerima masukan, memeriksa ukuran dan `kind`, mengubah teks
   data pribadi menjadi satu blob.
3. Anggota 2 menghasilkan tiga kunci acak, mengenkripsi tiga kali, mencatat
   waktu tiap enkripsi, dan membungkus tiap kunci dengan master key.
4. Layanan menulis tiga file ke `instance/storage/`.
5. Anggota 1 (layanan model) membuat satu `stored_file` dan tiga
   `cipher_copy` dalam **satu transaksi**. Gagal di mana pun berarti
   semuanya dibatalkan (I2).

### 8.2 Unduh (rancangan; pencarian bermilik sudah ada)

1. Pengguna memilih data dan algoritma (default AES; nilai selain
   `AES`/`DES`/`RC4` ditolak dengan 400).
2. Layanan mencari data berdasarkan `id` **dan** `owner_id` pengguna (I5).
   Data milik orang lain dijawab 404, sama seperti data yang tidak ada, agar
   keberadaannya tidak bocor. Sudah diterapkan oleh `get_owned_or_404` di
   `app/authz.py`; jawaban 404 yang identik dibuktikan oleh `tests/test_authz.py`.
3. Layanan membuka `wrapped_key` dengan master key, membaca file, dan
   Anggota 2 mendekripsinya.
4. Hasil dikirim dengan nama unduhan yang sudah dibersihkan.

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
- Mode non-ECB untuk AES/DES (CBC, CTR) dan RC4 tidak otentik: perubahan
  ciphertext tidak otomatis terdeteksi oleh algoritma itu sendiri.
- Metadata (`original_filename`, `kind`, ukuran, waktu) tersimpan plaintext.
- Tiga salinan memakan sekitar tiga kali ruang disk dan waktu enkripsi.
- Validasi `MASTER_KEY` memeriksa format dan panjang, bukan keacakan.
- Skema dibuat lewat `create_all()` tanpa migrasi. Mengubah skema selama
  pengembangan berarti menghapus `instance/app.db` dan menginisialisasi
  ulang; data uji hilang.
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
| Anggota 2 | Menyediakan: enkripsi satu blob menjadi tiga hasil (algoritma, mode, iv, kunci terbungkus, ciphertext, waktu) dan kebalikannya untuk satu salinan. Memilih mode dan format `wrapped_key`. Memastikan pustaka DES/RC4 (kemungkinan butuh PyCryptodome) dan menambahkannya ke `requirements.txt` bersama. Memutuskan apakah file diproses utuh di memori atau bertahap (memengaruhi bagian 9.1). |
| Anggota 3 | Menyediakan: formulir unggah, pemilihan algoritma saat unduh (default AES), pembersihan nama unduhan, validasi `kind` dan ukuran. Tidak membuat folder penyimpanan di jalur biasa. Tidak menyimpan apa pun di luar `instance/storage/`. |
| Anggota 1 | Sudah ada: model, `init_db.py` (membuat tabel dan folder), pendengar pragma FK, `app/authz.py` (`get_owned_or_404`, `owned_select`: pencarian yang selalu menyaring `owner_id`), konfigurasi `MASTER_KEY`, `STORAGE_DIR` dan `MAX_UPLOAD_MB`, autentikasi. Belum ada: layanan simpan/ambil/hapus berkas (bergantung pada modul enkripsi). |

## 13. Keputusan yang diambil (dulu pertanyaan terbuka)

| # | Pertanyaan | Keputusan | Bukti di repo |
| --- | --- | --- | --- |
| 1 | Data pribadi teks | Seragam sebagai `stored_file` dengan `kind=personal_data` | `KINDS` di `app/models.py` |
| 2 | Kunci per salinan atau per data | Per salinan (`wrapped_key` di `cipher_copy`); pembuatan kuncinya belum ada | `app/models.py` |
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
| Modul enkripsi AES/DES/RC4 | belum ada | milik Anggota 2 |
| Unggah, unduh, penyimpanan ciphertext | belum ada | milik Anggota 3 |
| Analisis performa | belum ada | |
