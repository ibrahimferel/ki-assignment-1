# Sharing API — handoff Member 3 ke Member 4

Panduan ini mengikuti [acuan Member 3](acuan_member3.md),
[routes](../app/sharing/routes.py), [services](../app/sharing/services.py),
[validation](../app/sharing/validation.py), dan
[tes integrasi](../tests/test_sharing_routes.py). Contoh ID, nama, dan waktu
di bawah bersifat ilustratif; `...` pada paket bukan paket yang valid.

## 1. Authentication dan CSRF

- Gunakan frontend dengan origin yang sama dengan Flask. Autentikasi memakai
  cookie session dari form `/auth/login`; tidak ada Bearer token/API login JSON.
- Seluruh endpoint sharing wajib login. Tanpa login, respons normal adalah
  `302` ke `/auth/login?next=...`. `fetch` mengikuti redirect dan dapat menerima
  HTML login dengan status akhir `200`; periksa `response.redirected`.
- Setiap POST memerlukan `X-CSRFToken`. Ambil dari
  `input[name="csrf_token"]` pada halaman aktif; halaman `/` setelah login
  sudah menyediakan input ini melalui form logout. Tidak ada endpoint CSRF khusus.
- Login mengosongkan session lama. Ambil token baru setelah login/reload;
  token milik session lain tidak berlaku. POST tanpa CSRF dapat mendapat `400`
  sebelum pemeriksaan login berjalan.
- POST dengan payload memakai `Content-Type: application/json`.
  GET dan POST reject/revoke tidak memerlukan body.

## 2. Endpoint Contract 3

`id` adalah ID access request; `file_id` adalah ID record owner.
Semua path di bawah tanpa trailing slash. Requester = pengaju akses;
owner = pemilik data yang diminta. Peran berlaku per request, bukan per akun.

| Method dan path | Aktor | Body JSON | Respons sukses |
|---|---|---|---|
| `POST /sharing/requests` | Requester | `{"username":"owner-b","reason":"Keperluan pemeriksaan"}` | `201 {"id":1}` |
| `GET /sharing/requests` | Keduanya | — | `200 {"incoming":[...],"outgoing":[...]}` |
| `POST /sharing/requests/<id>/approve` | Owner | `{"file_ids":[2,4]}` | `200 {"key_package":"..."}` |
| `GET /sharing/requests/<id>/key-package` | Owner | — | `200 {"key_package":"..."}` |
| `POST /sharing/requests/<id>/reject` | Owner | — | `204`, body kosong |
| `POST /sharing/requests/<id>/revoke` | Owner | — | `204`, body kosong |
| `POST /sharing/requests/<id>/unlock` | Requester | `{"key_package":"...","password":"password akun requester"}` | `200 {"files":[...],"unlocked_until":"..."}` |
| `GET /sharing/requests/<id>/files/<file_id>/download` | Requester | — | `200`, attachment; MIME `application/octet-stream`; nama dari original |
| `GET /sharing/requests/<id>/files/<file_id>/view` | Requester | — | `200`, inline `image/jpeg` atau `image/png` |
| `GET /sharing/requests/<id>/files/<file_id>/personal` | Requester | — | `200`, objek JSON data pribadi |

Ketiga endpoint file memerlukan request approved, belum expired, sudah
di-unlock dan window unlock masih berlaku, serta file termasuk pilihan approve.
Resource yang tidak tersedia/tidak berwenang menghasilkan `404`.

### Bentuk daftar request

```json
{
  "incoming": [],
  "outgoing": [
    {
      "id": 1,
      "username": "owner-b",
      "reason": "Keperluan pemeriksaan",
      "status": "approved",
      "created_at": "2026-11-17T08:00:00Z",
      "decided_at": "2026-11-17T09:00:00Z",
      "expires_at": "2026-11-24T09:00:00Z"
    }
  ]
}
```

- `incoming`: request dengan user aktif sebagai owner; `username` adalah requester.
  `outgoing`: user aktif sebagai requester; `username` adalah owner.
- Kedua list diurutkan ID menurun; list kosong berupa `[]`.
- Status hanya `pending`, `approved`, `rejected`, `revoked`. `decided_at` bernilai
  `null` ketika pending; `expires_at` bernilai `null` jika status bukan approved.
- Timestamp berupa ISO 8601 UTC dengan akhiran `Z`, dapat memuat mikrodetik.
- Listing tidak mengirim file, jumlah/ukuran file, atau key package,
  termasuk setelah approved. Daftar file berasal dari respons unlock.

### Respons unlock dan personal

```json
{
  "files": [
    {"id":2,"name":"id-card.png","kind":"id_card","content_type":"image/png","size":12345},
    {"id":4,"name":"document.pdf","kind":"document","content_type":"application/pdf","size":67890}
  ],
  "unlocked_until": "2026-11-17T09:15:00Z"
}
```

`size` adalah metadata ukuran plaintext dalam byte. `files` diurutkan ID file
menaik dan hanya memuat shared copy yang masih ada. Gunakan ID ini untuk
membentuk URL sharing; respons tidak memuat URL atau plaintext key.

`GET .../personal` hanya untuk `kind: "personal_data"`, dengan bentuk:

```json
{
  "nama": "Pemilik B",
  "nik": "0000000000000001",
  "alamat": "Jalan Contoh 1",
  "tanggal_lahir": "1990-01-01"
}
```

`view` hanya menerima MIME JPG/PNG. Gunakan `<img src="URL_VIEW">` atau buka
URL di tab baru; jangan iframe/object karena `X-Frame-Options: DENY` dan CSP.
Respons view memakai `sandbox; default-src 'none'; img-src 'self'`.
Gunakan link biasa untuk download. Respons non-static memakai `Cache-Control: no-store`.

## 3. Validasi dan alur UI

1. **Requester mengajukan:** username dinormalisasi trim/lowercase, ASCII 3–32
   karakter `a-z`, angka, `.`, `_`, `-`, diawali/diakhiri huruf atau angka.
   Reason di-trim, wajib tidak kosong, maksimal 500 karakter. Self-request dan
   duplikat pending pasangan yang sama ditolak `400`; username tidak ditemukan `404`.
2. **Kedua pihak melihat daftar:** gunakan incoming/outgoing. Jangan menampilkan
   metadata file owner kepada requester sebelum approval.
3. **Owner memilih file:** ambil `GET /storage/`, yang mengembalikan
   `{"items":[{"id":4,"name":"document.pdf","kind":"document","size":67890}]}`.
   Kirim ID pilihan secara eksplisit saat approve: 1–100 integer unik,
   rentang `1..2^63-1`, bukan string/bool. Semua file harus milik owner.
   Owner juga dapat reject request pending; sesudah keputusan, refresh daftar.
4. **Owner approve:** hanya pending. Backend membuat salinan terenkripsi terpisah
   dan mengembalikan paket RSA. Tampilkan sebagai teks untuk disalin utuh dan
   dikirim manual melalui kanal lain, misalnya WhatsApp/email. Backend tidak
   mengirim pesan tersebut. Owner dapat mengambil ulang paket selama share aktif
   melalui GET key-package; requester tidak dapat memakai endpoint ini.
5. **Requester unlock:** kirim paket utuh dan password akun requester, bukan
   password owner. Paket maksimal 2048 karakter; password string maksimal 1024
   karakter mentah. Jangan trim/mengubah password; normalisasi dilakukan backend.
   Paket/password kosong mencapai tahap crypto dan menghasilkan `422` pada share aktif.
   Setelah sukses, render `files` dan deadline dari respons.
6. **Requester membaca:** gunakan hanya URL `/sharing/...` untuk download/view/personal.
   URL `/storage/<id>/...` owner tetap ditolak bagi requester. Untuk personal data,
   tampilkan teks memakai `textContent`, bukan menyisipkan isi JSON sebagai HTML.
7. **Owner revoke:** hanya approved dengan kunci yang masih tersedia; hasil `204`.
   Backend menyimpan `revoked`, menghapus shared copy dan membatalkan unlock/paket.
   Refresh daftar; requester kehilangan akses, termasuk jika sebelumnya sudah unlock.

Approve/reject ulang pada request non-pending dan revoke ulang ditolak `400`.
Request baru boleh dibuat setelah request sebelumnya approved/rejected/revoked;
aturan unik hanya mencakup pending dengan arah requester–owner yang sama.

## 4. Error handling

| Status | Penyebab aktual | Tindakan frontend |
|---|---|---|
| `302` | Login diperlukan; fetch dapat berakhir pada HTML `200` | Deteksi redirect, arahkan ke login dan ambil CSRF baru sesudahnya |
| `400` | Payload/tipe/batas panjang salah, state tidak mengizinkan aksi, duplicate/self-request; requester belum punya keypair saat approve; atau CSRF gagal | Tampilkan pesan validasi; untuk CSRF, muat ulang halaman/login bila perlu |
| `404` | Resource hilang, peran salah, file bukan pilihan/milik owner, share tidak aktif/expired, belum unlock/window habis; view/personal tidak sesuai tipe | Jangan mencoba URL original; refresh daftar dan cek deadline, tawarkan unlock ulang jika share masih aktif |
| `422` | Password/paket salah, ID/label/kunci paket tidak cocok, keypair requester hilang saat unlock, ciphertext/JSON personal gagal dibaca | Tampilkan pesan generik; minta input ulang, jangan tampilkan exception internal |
| `429` | Unlock dibatasi | Baca `Retry-After` dalam detik dan tunda percobaan berikutnya |
| `413` | Melebihi limit body global `MAX_CONTENT_LENGTH` (default 50 MiB) | Tolak input terlalu besar; respons dapat berupa HTML |
| `500` | Kegagalan server yang tidak ditangani, misalnya I/O/DB | Tampilkan pesan umum; refresh state sebelum mengulang POST |

Error dari validator berupa `{"error":"pesan validasi"}`. Error crypto adalah
`{"error":"Data tidak dapat didekripsi"}`; throttle
`{"error":"Terlalu banyak percobaan"}`. File fisik hilang dapat memberi
`{"error":"Tidak ditemukan"}`. `abort(404)` dan error CSRF memakai HTML bawaan;
**jangan menganggap semua error JSON atau membedakan resource asing dari yang hilang**.
Tidak ada `409` pada implementasi sharing saat ini. `204` tidak boleh diparse sebagai JSON.

## 5. Contoh fetch

Letakkan JS di file statis eksternal; CSP halaman menolak inline script.
Helper ini untuk respons JSON/204, bukan file biner. Pesan error aplikasi
ditampilkan sebagai teks dan tidak perlu mencatat request body/password.

```javascript
async function sharingJSON(path, { method = "GET", body } = {}) {
  const headers = { Accept: "application/json" };
  if (method === "POST") {
    const token = document.querySelector('input[name="csrf_token"]')?.value;
    if (!token) throw new Error("Muat ulang halaman untuk memperoleh token CSRF.");
    headers["X-CSRFToken"] = token;
  }
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const response = await fetch(path, {
    method, headers, credentials: "same-origin",
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (response.redirected) {
    window.location.assign("/auth/login");
    throw new Error("Login kembali untuk melanjutkan.");
  }
  if (response.status === 204) return null;

  const isJSON = (response.headers.get("Content-Type") || "").includes("application/json");
  const data = isJSON ? await response.json() : null;
  if (!response.ok) {
    const message = data?.error || (response.status === 400
      ? "Permintaan ditolak; muat ulang halaman untuk memperbarui CSRF."
      : `HTTP ${response.status}`);
    const error = new Error(message);
    error.status = response.status;
    error.retryAfter = Number(response.headers.get("Retry-After") || 0);
    throw error;
  }
  if (!isJSON) throw new Error("Respons JSON tidak tersedia.");
  return data;
}

// Panggil sesuai peran/session; requestId dan input berasal dari UI/respons API.
const sendRequest = (username, reason) => sharingJSON("/sharing/requests", {
  method: "POST", body: { username, reason },
});
const listRequests = () => sharingJSON("/sharing/requests");
const approve = (requestId, fileIds) => sharingJSON(`/sharing/requests/${requestId}/approve`, {
  method: "POST", body: { file_ids: fileIds },
});
const unlock = (requestId, keyPackage, password) => sharingJSON(`/sharing/requests/${requestId}/unlock`, {
  method: "POST", body: { key_package: keyPackage, password },
});
const revoke = (requestId) => sharingJSON(`/sharing/requests/${requestId}/revoke`, { method: "POST" });
const personal = (requestId, fileId) => sharingJSON(`/sharing/requests/${requestId}/files/${fileId}/personal`);
```

Tangkap rejection dengan `try/catch` pada event handler. Error dengan `status: 429`
menyediakan `retryAfter`; kegagalan jaringan dari `fetch` juga masuk `catch`.
Jangan otomatis retry POST setelah koneksi terputus: aksi server mungkin sudah commit.

## 6. Batasan yang perlu diketahui Member 4

- Share berlaku 7 hari dari approval; unlock 15 menit dari unlock sukses.
  Akses harus memenuhi **kedua** deadline. Expiry/unlock bukan status tambahan;
  request expired tetap berstatus approved, jadi periksa `expires_at` juga.
  Share aktif dengan window habis dapat di-unlock ulang; expired/revoked perlu request baru.
- Limiter default mengizinkan lima percobaan unlock dalam 15 menit per pasangan
  user/request; setelah lima kegagalan, percobaan keenam `429`. Sukses mereset
  hitungan. Limiter berada di memori per aplikasi/proses dan tidak dibagi antar-worker.
- Tidak ada pagination, pencarian username, notifikasi, endpoint daftar file sharing
  terpisah, atau edit pilihan file setelah approval. Pada reload, listing tidak
  mengembalikan metadata/deadline unlock; API unlock dapat dipanggil ulang oleh requester.
- Shared ciphertext adalah snapshot saat approval; perubahan original tidak
  otomatis memperbaruinya. Penghapusan original menghapus shared copy terkait.
  Expiry menolak akses tetapi tidak otomatis menghapus ciphertext.
- Unlock berlaku per request, bukan per browser. Revoke tidak dapat menarik
  kembali file yang sudah diunduh. Jangan simpan password ke URL, log, cookie,
  localStorage atau sessionStorage; backend melakukan dekripsi, frontend tidak
  perlu mengimplementasikan RSA/AES atau menerima plaintext share key.
- Instalasi dengan database tiga-status lama harus menjalankan
  [migrasi status](../migrate_sharing_status.py) sebelum memakai revoke; lihat
  [README](../README.md). Database baru sudah mendukung status revoked.

Referensi perilaku yang telah diuji: [sharing routes](../tests/test_sharing_routes.py),
[crypto sharing](../tests/test_share_crypto.py),
[auth routes](../tests/test_auth_routes.py), dan
[security inventory](../tests/test_security_inventory.py).
