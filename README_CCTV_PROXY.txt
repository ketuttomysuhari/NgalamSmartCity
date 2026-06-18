CCTV Live Sidebar - Anti Mixed-Content Blocking

Yang diubah:
1. iframe CCTV tidak lagi langsung memakai URL http://stream.cctv.malangkota.go.id.
2. iframe diarahkan ke cctv_proxy.php?url=... agar halaman dashboard HTTPS tetap dapat memanggil stream HTTP.
3. Proxy dibatasi hanya untuk host stream.cctv.malangkota.go.id.

Cara menjalankan lokal:
1. Pastikan PHP tersedia.
2. Masuk ke folder dashboard.
3. Jalankan:
   php -S localhost:8080
4. Buka:
   http://localhost:8080/index.html

Cara deployment produksi:
Opsi A - PHP:
- Upload index.html, style.css, dan cctv_proxy.php ke hosting yang mendukung PHP.
- Buka dashboard melalui domain HTTPS Anda.

Opsi B - Nginx:
- Tambahkan isi nginx_cctv_proxy.conf ke server block HTTPS Anda.
- Di index.html, ubah:
  const CCTV_EMBED_MODE = "php";
  menjadi:
  const CCTV_EMBED_MODE = "nginx";

Catatan penting:
Proxy ini mengatasi mixed-content blocking dan X-Frame-Options dari respons yang diproxy.
Namun jika server CCTV/WebRTC menggunakan mekanisme token, origin check, WebSocket khusus, atau kebijakan internal lain, akses stream asli/HLS/WebRTC endpoint dari pengelola CCTV tetap diperlukan.
