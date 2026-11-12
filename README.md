# py-simpledefense v2.0

Menjaga server Linux dengan cara simpel, ringan, dan terukur.

`py-simpledefense` menggabungkan dua lapis pertahanan cerdas untuk server web berbasis Linux (**Apache 2.4 & Nginx** + PHP/Python/Node/Go + MariaDB/MySQL) tanpa memerlukan perangkat keras tambahan maupun dependensi pustaka eksternal:

1. **Lapis Pertama — Universal Web Server WAF (`Apache mod_rewrite` & `Nginx Rules`)**
   Menolak percobaan eksploitasi umum (`.env`, `.git`, `.sql`, SQL Injection, Directory Traversal/LFI, injeksi PHP webshell, XSS pada query string, hingga scanner otomatis seperti `sqlmap`/`nikto`/`nuclei`) secara instan dengan **HTTP 403 Forbidden** langsung di level server web sebelum menyentuh aplikasi atau database.
2. **Lapis Kedua — Active Defense & Real-Time Alerting (`csirt_active_defense.py`)**
   Daemon berbasis pustaka standar Python 3 yang memantau berkas `access.log` multi-vhost secara *real-time* (mendukung rotasi `logrotate` otomatis), mendeteksi anomali serangan, mengatur *rate-limit* notifikasi agar tidak membanjiri grup, mengirimkan laporan insiden ke **Telegram**, serta menyediakan opsi pemblokiran IP otomatis melalui `iptables` bagi penyerang berulang.

---

## Yang Baru di Versi 2.0 & 2.1 (Smart Auto-Discovery & Docker Firewall)

- **Simpel & Ramah Pengguna**: Tujuan utama `py-simpledefense` tetap dipertahankan: melindungi server secara otomatis tanpa mewajibkan admin memahami sintaks rumit regex Apache/Nginx maupun iptables.
- **Auto-Discovery Seluruh Direktori Web (`DocumentRoot` Scanner)**: Installer secara otomatis memindai seluruh VirtualHost aktif pada Apache dan Nginx (misal: `/var/www/`, `/home/*/public_html/`, `/srv/`, dll) dan langsung melindungi seluruh folder tersebut tanpa perlu konfigurasi manual!
- **Auto-Discovery Log Multi-Vhost (Log Wildcard / Globbing)**: Otomatis mendeteksi dan memantau seluruh berkas access log (`*access*.log`) dari semua domain/subdomain yang ada di server.
- **Deteksi Cerdas Paparan Port Docker & Pengamanan Firewall**: Mendeteksi jika ada container Docker yang membypass firewall host (terikat ke `0.0.0.0`), lalu secara interaktif dan aman menawarkan opsi penguncian via rantai `DOCKER-USER` (default aman: `Enter`).
- **Dukungan Penuh Nginx & Apache WAF (termasuk Reverse Proxy)**: Menyediakan modul WAF siap pakai baik untuk native web apps maupun container Docker di balik reverse proxy.
- **Preservasi Token & Konfigurasi Lama**: Saat melakukan upgrade, installer otomatis mempertahankan `TELEGRAM_BOT_TOKEN` dan Chat ID yang sudah aktif sebelumnya.
- **Zero pip install**: 100% menggunakan Python 3 standard library (`os`, `re`, `json`, `urllib`, `glob`).

---

## Struktur Repositori

```text
py-simpledefense/
├── csirt_active_defense.py          # Daemon pemantau log & pengirim alert Telegram (mendukung log wildcard)
├── deploy_defense.sh                # Installer cerdas v2.0 (Auto-Discovery DocumentRoot & multi-vhost log)
├── .env.example                     # Template konfigurasi environment
├── configs/
│   ├── apache-global-waf.conf       # Aturan blokir instan HTTP 403 di Apache 2.4
│   ├── nginx-global-waf.conf        # Aturan blokir instan HTTP 403 di Nginx (v2.0)
│   └── 99-mariadb-hardening.cnf     # Konfigurasi keamanan tambahan MariaDB/MySQL
├── systemd/
│   └── py-simpledefense.service     # Unit systemd untuk berjalan otomatis saat boot
├── LICENSE                          # Lisensi MIT
└── README.md                        # Dokumentasi penggunaan
```

---

## Cara Instalasi Cepat (Ubuntu / Debian)

### 1. Unduh Repositori

```bash
git clone https://github.com/muhammadtakdir/py-simpledefense.git
cd py-simpledefense
```

### 2. Jalankan Installer sebagai Root

```bash
sudo bash deploy_defense.sh
```

Installer v2.0 akan secara otomatis:
1. Memindai seluruh `DocumentRoot` web aktif di server Anda.
2. Memindai seluruh berkas log access Apache & Nginx.
3. Menghasilkan aturan WAF Apache / Nginx untuk semua folder web tersebut.
4. Memasang hardening database MariaDB/MySQL (`secure_file_priv`).
5. Mengaktifkan daemon systemd `py-simpledefense.service`.

### 3. Masukkan Kredensial Telegram (Sekali Saja)

Buka berkas konfigurasi yang telah dibuatkan installer:

```bash
sudo nano /etc/py-simpledefense/config.env
```

Cukup isi dua baris ini:
```ini
TELEGRAM_BOT_TOKEN=1234567890:AAExampleTokenDariBotFather
TELEGRAM_CHAT_IDS=123456789,@nama_channel_csirt
```

Lalu muat ulang daemon:
```bash
sudo systemctl restart py-simpledefense
```

---

## Pengujian & Operasional

### 1. Uji Pengiriman Notifikasi Telegram

```bash
sudo SIMPLEDEFENSE_ENV=/etc/py-simpledefense/config.env \
  python3 /opt/py-simpledefense/csirt_active_defense.py --test-alert
```

### 2. Uji Blokir WAF dari Komputer Lain

Uji akses ke berkas sensitif semu:
```bash
curl -i https://domain-anda.contoh/.env
```
Respons yang diharapkan adalah **HTTP 403 Forbidden**, disertai notifikasi instan ke Telegram Anda.

### 3. Memantau Log Service

```bash
sudo journalctl -u py-simpledefense -f
```

---

## Lisensi

Dirilis di bawah [MIT License](LICENSE) — Hak Cipta (c) 2026 Muhammad Takdir.
