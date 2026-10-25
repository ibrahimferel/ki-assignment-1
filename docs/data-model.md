# Model Data (CP2) - Rencana dan Penjelasan

Status: **DRAF, menunggu persetujuan Anggota 1.** Dokumen ini belum berisi
kode. Tidak ada tabel yang dibuat sebelum dokumen ini disetujui (kode model
baru ditulis di CP3).

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
| 4 | `MAX_UPLOAD_MB` | Diusulkan **50** (bagian 9, menunggu persetujuan) |

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
(tabel kolom terenkripsi terpisah) ada di pertanyaan terbuka nomor 1.

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
  (usulan 3 sampai 32 karakter, huruf/angka/garis bawah) ditetapkan di CP5.
- Hash memakai fungsi bawaan Werkzeug. Versi default Werkzeug 3.x memakai
  scrypt, yang butuh dukungan `hashlib.scrypt` di Python. **Belum diperiksa
  di Python 3.9.6 pada Mac Anda** (build macOS tertentu tidak
  menyertakannya). Ini diperiksa di awal CP5; jika tidak ada, metode hash
  ditetapkan eksplisit (misalnya pbkdf2) dan dicatat di laporan.

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
| I1 | Setiap `stored_file` punya tepat tiga `cipher_copy` (AES, DES, RC4) | layanan unggah (satu transaksi) | CP3/CP5, tes model dan layanan |
| I2 | Tidak ada `stored_file` setengah jadi: salah satu enkripsi gagal berarti seluruh unggahan dibatalkan | layanan unggah | tes dengan kegagalan yang disuntikkan |
| I3 | `UNIQUE (file_id, algorithm)` dan `UNIQUE (storage_name)` | database | CP3, tes model |
| I4 | Hapus pengguna atau data menghapus baris turunannya | database (FK cascade) | CP3, tes model |
| I5 | Setiap akses data lewat `owner_id` pengguna yang login | layanan akses | CP7, CP8 |
| I6 | Kunci tidak pernah ditulis ke log, pesan galat, atau database dalam bentuk mentah | semua; ditinjau di CP8 | CP8, pencarian dan tes |

**Peringatan SQLite (penting untuk I3 dan I4):** SQLite mengabaikan foreign
key dan cascade kecuali `PRAGMA foreign_keys=ON` dijalankan pada **setiap
koneksi**. Flask-SQLAlchemy tidak melakukannya otomatis. Rencana CP3:
pasang pendengar peristiwa koneksi untuk mengaktifkannya, dan tulis tes yang
membuktikan baris turunan benar-benar terhapus (tes ini harus gagal dulu
jika pragma dimatikan).

## 7. Penyimpanan ciphertext

- Lokasi: `instance/storage/`, satu file per `cipher_copy`, bernama
  `storage_name` (string acak, bukan dari masukan pengguna).
- Pembuat folder: **perintah inisialisasi basis data (CP3)**, idempoten, izin
  `0700`. Kode Anggota 3 mengasumsikan folder sudah ada dan tidak membuatnya
  sendiri di jalur biasa.
- Lokasi diatur lewat konfigurasi (`STORAGE_DIR`); `TestingConfig` memakai
  folder sementara yang unik per instance dan dihapus setelah tes.
- Urutan tulis saat unggah: tulis semua file ke disk, lalu commit database.
  Jika commit gagal, file yang sudah ditulis dihapus. Sebaliknya saat hapus:
  hapus baris database, lalu file. File yatim (ada di disk, tidak di
  database) tidak berbahaya tetapi dicatat dan diuji; baris tanpa file
  tidak boleh terjadi.

## 8. Alur

### 8.1 Unggah

1. Pengguna login; rute unggah memeriksa sesi (CP6).
2. Anggota 3 menerima masukan, memeriksa ukuran dan `kind`, mengubah teks
   data pribadi menjadi satu blob.
3. Anggota 2 menghasilkan tiga kunci acak, mengenkripsi tiga kali, mencatat
   waktu tiap enkripsi, dan membungkus tiap kunci dengan master key.
4. Layanan menulis tiga file ke `instance/storage/`.
5. Anggota 1 (layanan model) membuat satu `stored_file` dan tiga
   `cipher_copy` dalam **satu transaksi**. Gagal di mana pun berarti
   semuanya dibatalkan (I2).

### 8.2 Unduh

1. Pengguna memilih data dan algoritma (default AES; nilai selain
   `AES`/`DES`/`RC4` ditolak dengan 400).
2. Layanan mencari data berdasarkan `id` **dan** `owner_id` pengguna (I5).
   Data milik orang lain dijawab 404, sama seperti data yang tidak ada, agar
   keberadaannya tidak bocor. (Dikonfirmasi di CP7.)
3. Layanan membuka `wrapped_key` dengan master key, membaca file, dan
   Anggota 2 mendekripsinya.
4. Hasil dikirim dengan nama unduhan yang sudah dibersihkan.

## 9. Konfigurasi baru dan usulan `MAX_UPLOAD_MB`

Perubahan pada `app/config.py` dan `.env.example` **bukan bagian dokumen
ini**; ia dikerjakan sebagai checkpoint terpisah dengan persetujuan:

| Variabel | Aturan |
| --- | --- |
| `MASTER_KEY` | wajib; heksadesimal 64 karakter (32 byte); tidak boleh sama dengan `SECRET_KEY`; gagal start jika salah (gaya `ConfigError`) |
| `STORAGE_DIR` | opsional; default `instance/storage` |
| `MAX_UPLOAD_MB` | usulan nilai awal 50 (di bawah) |

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

Konsekuensi mengubah angka dari 100 ke 50: `DEFAULT_MAX_UPLOAD_MB` di
`app/config.py`, nilai di `.env.example`, dan ekspektasi di
`verify_config.py` harus diubah bersama (satu checkpoint, diuji ulang).

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

## 11. Gaya model dan hal teknis

- Usulan gaya model: **`db.Column` klasik** untuk seluruh tim. Alasan: lebih
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
| Anggota 1 | Menyediakan: model, perintah inisialisasi database (membuat tabel dan folder), pendengar pragma FK, layanan simpan/ambil/hapus yang selalu menyaring `owner_id`, konfigurasi `MASTER_KEY` dan `STORAGE_DIR`. |

## 13. Pertanyaan terbuka (butuh jawaban Anda)

1. **Data pribadi teks**: setuju diperlakukan seragam sebagai `stored_file`
   dengan `kind=personal_data` (bagian 2.1)? Alternatif: tabel terpisah
   dengan kolom terenkripsi, lebih mirip "basis data" biasa tetapi menambah
   jalur kode.
2. **Kunci per salinan** (bagian 5) atau satu kunci per data dengan
   turunan per algoritma? Rekomendasi: per salinan.
3. **Nilai `MAX_UPLOAD_MB`**: 50 (rekomendasi) atau tetap 100?
4. **404 untuk data milik orang lain** (bagian 8.2) sebagai arah awal?
5. **Gaya model**: `db.Column` (rekomendasi) atau `Mapped[...]`?
6. **`encrypt_seconds` disimpan di database** (bagian 5), atau analisis
   performa hanya lewat skrip benchmark terpisah?
7. **`.gitignore` tanpa `*.db`**: ditambahkan sebagai pengaman, atau
   dibiarkan karena basis data ada di `instance/`?

## 14. Rencana checkpoint berikutnya (belum dikerjakan)

| CP | Isi | Menyentuh file |
| --- | --- | --- |
| CP2b | Ubah konfigurasi: `MASTER_KEY`, `STORAGE_DIR`, `MAX_UPLOAD_MB` | `app/config.py`, `.env.example`, `verify_config.py` |
| CP3 | Model, pragma FK, perintah inisialisasi database + folder penyimpanan | `app/models.py`, `app/__init__.py` (atau `app/db_init.py`) |
| CP4 | Infrastruktur tes | `tests/conftest.py` |
| CP5 | Layanan autentikasi | `app/auth/services.py` |
| CP6 | Rute autentikasi, cookie sesi | `app/auth/routes.py`, `requirements.txt` |
| CP7 | Otorisasi | layanan akses |
| CP8 | Tes integrasi dan keamanan | `tests/` |
| CP9 | Dokumentasi dan penggabungan | `docs/` |

Tiap checkpoint dikerjakan satu unit kecil, dengan tinjauan dan pengujian,
lalu berhenti untuk persetujuan.
