# py-simpledefense

Menjaga server Linux dengan cara simpel, ringan, dan terukur.

`py-simpledefense` menggabungkan dua lapis pertahanan ringan untuk server web berbasis Linux (Apache + PHP/Python/Node + MariaDB/MySQL) tanpa memerlukan perangkat keras tambahan maupun dependensi pustaka eksternal:

1. **Lapis Pertama — Web Server Shield (`Apache mod_rewrite` & `mod_headers`)**
   Menolak percobaan eksploitasi umum (`.env`, `.git`, `.sql`, SQL Injection, Directory Traversal/LFI, injeksi PHP webshell, XSS pada query string, hingga scanner otomatis seperti `sqlmap`/`nikto`) secara instan dengan **HTTP 403 Forbidden** langsung di level C Apache sebelum menyentuh aplikasi atau database.
2. **Lapis Kedua — Active Defense & Real-Time Alerting (`csirt_active_defense.py`)**
   Daemon berbasis pustaka standar Python 3 yang memantau berkas `access.log` secara *real-time* (mendukung rotasi `logrotate` otomatis), mendeteksi anomali serangan, mengatur *rate-limit* notifikasi agar tidak membanjiri grup, mengirimkan laporan insiden ke **Telegram**, serta menyediakan opsi pemblokiran IP otomatis melalui `iptables` bagi penyerang berulang.

---

## Fitur Utama

- **Tanpa Dependensi Eksternal (`Zero pip install`)**: Hanya menggunakan pustaka bawaan Python 3 (`os`, `re`, `json`, `urllib`, `subprocess`), sehingga aman dijalankan di berbagai distribusi server produksi.
- **Hemat CPU & RAM**: Beban penolakan trafik berbahaya ditangani langsung oleh web server (403 Forbidden), menjaga beban PHP-FPM dan database tetap rendah saat terjadi gempuran botnet.
- **Tahan Terhadap Log Rotation**: Mendeteksi pergantian *inode* berkas log saat `logrotate` berjalan tengah malam tanpa perlu me-restart service.
- **Konfigurasi Terpusat via `.env`**: Seluruh token bot, daftar Chat ID Telegram, daftar *log path*, dan *whitelist* IP terpisah dari kode sumber.
- **Hardening Database Pendamping**: Menyertakan konfigurasi MariaDB/MySQL (`secure_file_priv` dan penguncian `bind-address = 127.0.0.1`) untuk menutup celah penulisan *webshell* via `INTO OUTFILE`.

---

## Struktur Repositori

```text
py-simpledefense/
├── csirt_active_defense.py          # Daemon pemantau log & pengirim alert Telegram
├── deploy_defense.sh                # Skrip instalasi otomatis (WAF + Hardening + Systemd)
├── .env.example                     # Template konfigurasi environment
├── configs/
│   ├── apache-global-waf.conf       # Aturan blokir instan HTTP 403 di Apache 2.4
│   └── 99-mariadb-hardening.cnf     # Konfigurasi keamanan tambahan MariaDB/MySQL
├── systemd/
│   └── py-simpledefense.service     # Unit systemd untuk berjalan otomatis saat boot
└── LICENSE                          # Lisensi MIT
```

---

## Cara Instalasi Cepat (Ubuntu / Debian)

### 1. Unduh Repositori

```bash
git clone https://github.com/muhammadtakdir/py-simpledefense.git
cd py-simpledefense
```

### 2. Siapkan Konfigurasi `.env`

Salin template `.env.example` menjadi `.env`, lalu sesuaikan identitas server, Token Bot Telegram (dari `@BotFather`), dan Chat ID tujuan:

```bash
cp .env.example .env
nano .env
```

Contoh isi `.env`:

```ini
SERVER_LABEL=portal.contoh.go.id
SERVER_PUBLIC_IP=203.0.113.10
TIMEZONE_LABEL=WITA

TELEGRAM_BOT_TOKEN=1234567890:AAExampleTokenDariBotFather
TELEGRAM_CHAT_IDS=@grup_monitoring_server,123456789

LOG_FILES=/var/log/apache2/access.log,/var/log/apache2/other_vhosts_access.log
WHITELIST_IPS=127.0.0.1,::1

ALERT_COOLDOWN_SECONDS=300
AUTO_BAN_ENABLED=false
```

### 3. Jalankan Installer sebagai Root

```bash
sudo bash deploy_defense.sh
```

Skrip installer akan:
1. Menyalin daemon ke `/opt/py-simpledefense/csirt_active_defense.py` dan mengunci konfigurasi di `/etc/py-simpledefense/config.env` (`chmod 600`).
2. Mengaktifkan modul Apache `rewrite` serta `headers`, memasang `py-simpledefense-waf.conf`, menguji sintaks dengan `apache2ctl configtest`, lalu memuat ulang Apache.
3. Menyalin konfigurasi hardening `99-mariadb-hardening.cnf` apabila MariaDB/MySQL terdeteksi.
4. Mendaftarkan dan menjalankan service `py-simpledefense.service` di `systemd`.

---

## Pengujian & Operasional

### Menguji Konfigurasi & Pengiriman Telegram

```bash
# Cek pembacaan konfigurasi
sudo SIMPLEDEFENSE_ENV=/etc/py-simpledefense/config.env \
  python3 /opt/py-simpledefense/csirt_active_defense.py --check-config

# Kirim pesan uji coba ke Telegram
sudo SIMPLEDEFENSE_ENV=/etc/py-simpledefense/config.env \
  python3 /opt/py-simpledefense/csirt_active_defense.py --test-alert
```

### Menguji Blokir WAF dari Komputer Lain

Dari komputer di luar *whitelist*, uji akses ke berkas sensitif semu:

```bash
curl -i https://domain-anda.contoh/.env
```

Respons yang diharapkan dari server adalah `HTTP/1.1 403 Forbidden`, disertai notifikasi instan ke Telegram Anda dalam hitungan detik.

### Memantau Log Service

```bash
sudo journalctl -u py-simpledefense -f
```

---

## Mode Auto-Ban Firewall (Opsional)

Secara bawaan `AUTO_BAN_ENABLED=false` karena penolakan `HTTP 403` oleh Apache sudah sangat ringan dan mencegah tabel `iptables` membengkak oleh ribuan IP botnet sekali pakai.

Apabila Anda tetap ingin memblokir penuh paket jaringan dari IP yang menyerang berulang kali dalam waktu singkat, ubah pengaturan berikut di `/etc/py-simpledefense/config.env`:

```ini
AUTO_BAN_ENABLED=true
AUTO_BAN_THRESHOLD=10
AUTO_BAN_WINDOW_SECONDS=120
```

> **Penting:** Pastikan IP manajemen/VPN Anda sudah dimasukkan ke dalam `WHITELIST_IPS` sebelum mengaktifkan fitur auto-ban atau melakukan pengujian mandiri.

---

## Lisensi

Dirilis di bawah [MIT License](LICENSE) — Hak Cipta (c) 2026 Muhammad Takdir.
