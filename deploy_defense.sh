#!/usr/bin/env bash
# ==============================================================================
# py-simpledefense v2.0 - Universal Installer & Auto-Hardening Script
# Mendukung Apache 2.4 & Nginx (Ubuntu / Debian)
# Fitur Unggulan:
# 1. Auto-Discovery semua DocumentRoot / folder web (baik di /var/www, /home, /srv, dll)
# 2. Auto-Discovery seluruh berkas access log (Apache & Nginx multi-vhost)
# 3. Auto-Detect Nginx & Apache WAF deployment
# 4. MariaDB / MySQL hardening (secure_file_priv & localhost bind)
# 5. Preservasi token bot Telegram & konfigurasi lama saat upgrade
# ==============================================================================
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/py-simpledefense"
CONFIG_DIR="/etc/py-simpledefense"
CONFIG_FILE="${CONFIG_DIR}/config.env"
SERVICE_DEST="/etc/systemd/system/py-simpledefense.service"
APACHE_CONF_DEST="/etc/apache2/conf-available/py-simpledefense-waf.conf"
NGINX_SNIPPET_DIR="/etc/nginx/snippets"
NGINX_CONF_DEST="${NGINX_SNIPPET_DIR}/py-simpledefense-waf.conf"

info() { echo -e "\e[1;34m[*] $*\e[0m"; }
ok()   { echo -e "\e[1;32m[+] $*\e[0m"; }
warn() { echo -e "\e[1;33m[!] $*\e[0m"; }
die()  { echo -e "\e[1;31m[-] Error: $*\e[0m" >&2; exit 1; }

echo "=================================================================="
echo "    py-simpledefense v2.0 - Universal Web Server Hardening & WAF  "
echo "=================================================================="

if [[ "${EUID}" -ne 0 ]]; then
    die "Jalankan installer ini sebagai root (contoh: sudo bash deploy_defense.sh)"
fi

# ------------------------------------------------------------------------------
# 1. Menyiapkan Direktori & Kode Python
# ------------------------------------------------------------------------------
info "1. Menyiapkan direktori instalasi & modul daemon..."
mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}"
cp -f "${BASE_DIR}/csirt_active_defense.py" "${INSTALL_DIR}/csirt_active_defense.py"
chmod 750 "${INSTALL_DIR}/csirt_active_defense.py"

# ------------------------------------------------------------------------------
# 2. Auto-Discovery Direktori Web (DocumentRoot Scanner)
# ------------------------------------------------------------------------------
info "2. Menjalankan auto-discovery direktori aplikasi web..."
FOUND_DIRS=()

# Direktori web standar umum & aaPanel / BT-Panel
[[ -d "/var/www" ]] && FOUND_DIRS+=("/var/www/")
[[ -d "/www/wwwroot" ]] && FOUND_DIRS+=("/www/wwwroot/")

# Pindai DocumentRoot dari Apache (Debian/Ubuntu standar & aaPanel)
APACHE_SITES_DIRS=(
    "/etc/apache2/sites-enabled"
    "/etc/apache2/conf-enabled"
    "/www/server/panel/vhost/apache"
    "/www/server/apache/conf/vhost"
)
for sdir in "${APACHE_SITES_DIRS[@]}"; do
    if [[ -d "${sdir}" ]]; then
        while IFS= read -r dir; do
            if [[ -n "${dir}" && -d "${dir}" ]]; then
                if [[ "${dir}" =~ ^/home/[^/]+/public_html ]]; then
                    FOUND_DIRS+=("${BASH_REMATCH[0]}/")
                else
                    FOUND_DIRS+=("${dir%/}/")
                fi
            fi
        done < <(grep -hE "^\s*DocumentRoot\s+" "${sdir}"/* 2>/dev/null | awk '{print $2}' | tr -d '"' | tr -d "'" | sort -u || true)
    fi
done

# Pindai root dari Nginx (Debian/Ubuntu standar & aaPanel)
NGINX_SITES_DIRS=(
    "/etc/nginx/sites-enabled"
    "/etc/nginx/conf.d"
    "/www/server/panel/vhost/nginx"
    "/www/server/nginx/conf/vhost"
)
for sdir in "${NGINX_SITES_DIRS[@]}"; do
    if [[ -d "${sdir}" ]]; then
        while IFS= read -r dir; do
            if [[ -n "${dir}" && -d "${dir}" ]]; then
                if [[ "${dir}" =~ ^/home/[^/]+/public_html ]]; then
                    FOUND_DIRS+=("${BASH_REMATCH[0]}/")
                else
                    FOUND_DIRS+=("${dir%/}/")
                fi
            fi
        done < <(grep -hE "^\s*root\s+" "${sdir}"/* 2>/dev/null | awk '{print $2}' | tr -d ';' | tr -d '"' | sort -u || true)
    fi
done

# Deduplikasi daftar direktori web
UNIQUE_DIRS=($(printf "%s\n" "${FOUND_DIRS[@]}" | sort -u))
info "   Direktori web terdeteksi untuk dilindungi WAF:"
for d in "${UNIQUE_DIRS[@]}"; do
    echo "    -> ${d}"
done

# ------------------------------------------------------------------------------
# 3. Auto-Discovery Berkas Log Access (Apache, Nginx, aaPanel)
# ------------------------------------------------------------------------------
info "3. Menjalankan auto-discovery berkas access log..."
FOUND_LOGS=()

# Cari log Apache standar & aaPanel
for p in /var/log/apache2/*access*.log /var/log/httpd/*access*.log /www/wwwlogs/*access*.log /www/wwwlogs/*-access_log; do
    [[ -f "${p}" ]] && FOUND_LOGS+=("${p}")
done

# Cari log Nginx
for p in /var/log/nginx/*access*.log; do
    [[ -f "${p}" ]] && FOUND_LOGS+=("${p}")
done

# Cari access_log umum di aaPanel /www/wwwlogs/access_log
[[ -f "/www/wwwlogs/access_log" ]] && FOUND_LOGS+=("/www/wwwlogs/access_log")

# Jika belum ada file spesifik, pasang pola glob standar
if [[ ${#FOUND_LOGS[@]} -eq 0 ]]; then
    FOUND_LOGS+=("/var/log/apache2/*access*.log" "/var/log/nginx/*access*.log" "/var/log/apache2/access.log")
fi

DISCOVERED_LOG_FILES=$(printf "%s," "${FOUND_LOGS[@]}" | sed 's/,$//')
info "   Berkas log yang akan dipantau:"
for l in "${FOUND_LOGS[@]}"; do
    echo "    -> ${l}"
done

# ------------------------------------------------------------------------------
# 4. Pembuatan / Preservasi Konfigurasi Environment (config.env)
# ------------------------------------------------------------------------------
info "4. Mengonfigurasi environment (/etc/py-simpledefense/config.env)..."

HOSTNAME_LABEL="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo 'server.local')"
DETECTED_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' || echo '-')"

if [[ -f "${CONFIG_FILE}" ]]; then
    info "   -> Berkas config.env yang sudah ada ditemukan, mempertahankan token & preferensi lama..."
    if grep -q "^LOG_FILES=" "${CONFIG_FILE}"; then
        sed -i "s|^LOG_FILES=.*|LOG_FILES=${DISCOVERED_LOG_FILES}|" "${CONFIG_FILE}"
    else
        echo "LOG_FILES=${DISCOVERED_LOG_FILES}" >> "${CONFIG_FILE}"
    fi
else
    if [[ -f "${BASE_DIR}/.env" ]]; then
        cp "${BASE_DIR}/.env" "${CONFIG_FILE}"
        info "   -> Menggunakan pengaturan dari .env lokal."
    else
        cat << ENV_EOF > "${CONFIG_FILE}"
# Konfigurasi py-simpledefense v2.0
SERVER_LABEL=${HOSTNAME_LABEL}
SERVER_PUBLIC_IP=${DETECTED_IP}
TIMEZONE_LABEL=WITA

# Kredensial Bot Telegram (dibuat via @BotFather)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_IDS=

# Target log (otomatis terdeteksi seluruh vhost)
LOG_FILES=${DISCOVERED_LOG_FILES}

# IP tepercaya (whitelist)
WHITELIST_IPS=127.0.0.1,::1

# Cooldown per IP (detik)
ALERT_COOLDOWN_SECONDS=300

# Auto-ban iptables
AUTO_BAN_ENABLED=false
AUTO_BAN_THRESHOLD=10
AUTO_BAN_WINDOW_SECONDS=120
ENV_EOF
        warn "   -> Berkas config.env baru dibuat di ${CONFIG_FILE}."
        warn "      Silakan isi TELEGRAM_BOT_TOKEN & TELEGRAM_CHAT_IDS setelah instalasi selesai."
    fi
fi
chmod 600 "${CONFIG_FILE}"

# ------------------------------------------------------------------------------
# 5. Memasang Aturan Apache WAF (Jika Apache Terpasang)
# ------------------------------------------------------------------------------
APACHE_BIN=""
command -v /www/server/apache/bin/httpd >/dev/null 2>&1 && APACHE_BIN="/www/server/apache/bin/httpd"
[[ -z "${APACHE_BIN}" ]] && command -v apache2ctl >/dev/null 2>&1 && APACHE_BIN="apache2ctl"

if [[ -n "${APACHE_BIN}" ]]; then
    info "5. Memasang & menghasilkan aturan Apache Global WAF (${APACHE_BIN})..."
    
    # Deteksi lokasi conf Apache (aaPanel diutamakan bila binary aaPanel terdeteksi)
    APACHE_CONF_DIR=""
    if [[ "${APACHE_BIN}" == "/www/server/apache/bin/httpd" && -d "/www/server/apache/conf" ]]; then
        APACHE_CONF_DIR="/www/server/apache/conf"
        APACHE_TARGET_CONF="${APACHE_CONF_DIR}/py-simpledefense-waf.conf"
        # Tambahkan include ke httpd.conf aaPanel jika belum ada
        if ! grep -q "py-simpledefense-waf.conf" "/www/server/apache/conf/httpd.conf"; then
            echo "IncludeOptional conf/py-simpledefense-waf.conf" >> "/www/server/apache/conf/httpd.conf"
        fi
    elif [[ -d "/etc/apache2/conf-available" ]]; then
        APACHE_CONF_DIR="/etc/apache2/conf-available"
        APACHE_TARGET_CONF="${APACHE_CONF_DIR}/py-simpledefense-waf.conf"
        command -v a2enmod >/dev/null 2>&1 && a2enmod rewrite headers >/dev/null 2>&1 || true
    fi

    if [[ -n "${APACHE_CONF_DIR}" ]]; then
        cat << APACHE_HEAD_EOF > "${APACHE_TARGET_CONF}"
# ==============================================================================
# py-simpledefense v2.0 - Universal Apache WAF
# Otomatis dihasilkan oleh installer untuk seluruh direktori web yang terdeteksi
# ==============================================================================
ServerTokens Prod
ServerSignature Off

<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>
APACHE_HEAD_EOF

        for target_dir in "${UNIQUE_DIRS[@]}"; do
            cat << DIR_EOF >> "${APACHE_TARGET_CONF}"

<Directory ${target_dir}>
    <IfModule mod_rewrite.c>
        RewriteEngine On
        RewriteOptions InheritDownBefore

        # 1. Blokir akses ke file sensitif & repositori
        RewriteRule (?i)(^|/)(\.env|\.git|\.svn|\.bzr|\.hg) - [F,L]
        RewriteRule (?i)\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist)$ - [F,L]
        RewriteRule (?i)(composer\.(json|lock)|package\.(json|lock)|web\.config) - [F,L]

        # 2. Blokir probing panel database & exploit CMS
        RewriteRule (?i)(phpmyadmin|pma|adminer|wp-config\.php|xmlrpc\.php) - [F,L]

        # 3. Blokir SQL Injection pada Query String
        RewriteCond %{QUERY_STRING} (?i)(union.*select|select.*from|into.*outfile|into.*dumpfile) [NC,OR]
        RewriteCond %{QUERY_STRING} (?i)(benchmark\s*\(|waitfor\s+delay|sleep\s*\(|load_file\s*\() [NC,OR]
        RewriteCond %{QUERY_STRING} (?i)(\b(drop|alter|truncate)\s+(table|database)) [NC]
        RewriteRule ^.*$ - [F,L]

        # 4. Blokir Path Traversal / LFI
        RewriteCond %{QUERY_STRING} (?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self/environ|win\.ini) [NC,OR]
        RewriteCond %{REQUEST_URI} (?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self/environ|win\.ini) [NC]
        RewriteRule ^.*$ - [F,L]

        # 5. Blokir Injeksi Fungsi PHP Berbahaya
        RewriteCond %{QUERY_STRING} (?i)(eval\s*\(|base64_decode\s*\(|passthru\s*\(|shell_exec\s*\(|system\s*\(|assert\s*\() [NC,OR]
        RewriteCond %{QUERY_STRING} (?i)(php://input|data://text|phar://) [NC]
        RewriteRule ^.*$ - [F,L]

        # 6. Blokir Reflected XSS
        RewriteCond %{QUERY_STRING} (?i)(<script|%3Cscript|javascript:|alert\s*\(|onerror=|onload=|<svg|%3Csvg) [NC]
        RewriteRule ^.*$ - [F,L]

        # 7. Blokir User-Agent pemindai otomatis
        RewriteCond %{HTTP_USER_AGENT} (?i)(nikto|sqlmap|acunetix|havij|nmap|dirbuster|gobuster|wpscan|nuclei) [NC]
        RewriteRule ^.*$ - [F,L]
    </IfModule>
</Directory>
DIR_EOF
        done

        # Tambahkan perisai global pada level Location (melindungi Reverse Proxy ke Docker container)
        cat << LOCATION_WAF_EOF >> "${APACHE_TARGET_CONF}"

# ==============================================================================
# Perisai Global Level Location (Melindungi VirtualHost ProxyPass / Docker Container)
# ==============================================================================
<LocationMatch "(?i)(\.env|\.git|\.sql|\.bak|composer\.lock|wp-config\.php)">
    Require all denied
</LocationMatch>

<LocationMatch "(?i)/(adminer|phpmyadmin|pma)(\.php|/)">
    Require all denied
</LocationMatch>
LOCATION_WAF_EOF

        if [[ -d "/etc/apache2/conf-available" && "${APACHE_BIN}" == "apache2ctl" ]]; then
            a2enconf py-simpledefense-waf >/dev/null 2>&1 || true
            if apache2ctl configtest >/dev/null 2>&1; then
                systemctl reload apache2
                ok "   Apache WAF aktif dan terkonfigurasi untuk seluruh direktori web."
            else
                warn "   apache2ctl configtest gagal. Memulihkan konfigurasi sebelumnya..."
                a2disconf py-simpledefense-waf >/dev/null 2>&1 || true
            fi
        elif [[ "${APACHE_BIN}" == "/www/server/apache/bin/httpd" ]]; then
            if "${APACHE_BIN}" -t >/dev/null 2>&1; then
                /www/server/apache/bin/httpd -k graceful >/dev/null 2>&1 || systemctl reload httpd 2>/dev/null || /etc/init.d/httpd reload 2>/dev/null || true
                ok "   Apache aaPanel WAF aktif dan sintaks valid."
            else
                warn "   Apache httpd -t gagal. Memeriksa konfigurasi..."
            fi
        fi
    fi
else
    info "   Apache2 tidak terdeteksi, melewati konfigurasi Apache."
fi

# ------------------------------------------------------------------------------
# 6. Memasang Aturan Nginx WAF (Jika Nginx Terpasang)
# ------------------------------------------------------------------------------
if command -v nginx >/dev/null 2>&1 && [[ -d "/etc/nginx" ]]; then
    info "6. Memasang aturan Nginx WAF..."
    mkdir -p "${NGINX_SNIPPET_DIR}"
    cp -f "${BASE_DIR}/configs/nginx-global-waf.conf" "${NGINX_CONF_DEST}"
    ok "   Snippet Nginx WAF terpasang di ${NGINX_CONF_DEST}."
    info "   Untuk mengaktifkannya pada server block Nginx, tambahkan:"
    info "   include /etc/nginx/snippets/py-simpledefense-waf.conf; di dalam blok 'server { ... }'."
    if nginx -t >/dev/null 2>&1; then
        ok "   Sintaks Nginx valid."
    fi
fi

# ------------------------------------------------------------------------------
# 7. Memasang Hardening MariaDB / MySQL
# ------------------------------------------------------------------------------
if [[ -d "/etc/mysql/mariadb.conf.d" ]] || [[ -d "/etc/mysql/conf.d" ]]; then
    info "7. Memasang hardening MariaDB / MySQL (secure_file_priv & bind localhost)..."
    mkdir -p /var/lib/mysql-files
    chown mysql:mysql /var/lib/mysql-files 2>/dev/null || true
    chmod 700 /var/lib/mysql-files

    TARGET_MYSQL_CONF="/etc/mysql/conf.d/99-mariadb-hardening.cnf"
    [[ -d "/etc/mysql/mariadb.conf.d" ]] && TARGET_MYSQL_CONF="/etc/mysql/mariadb.conf.d/99-mariadb-hardening.cnf"
    cp -f "${BASE_DIR}/configs/99-mariadb-hardening.cnf" "${TARGET_MYSQL_CONF}"
    ok "   Hardening disalin ke ${TARGET_MYSQL_CONF}."
fi

# ------------------------------------------------------------------------------
# 8. Deteksi Cerdas Port Docker & Pengamanan Firewall Interaktif
# ------------------------------------------------------------------------------
if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker 2>/dev/null; then
    info "8. Memeriksa paparan port container Docker..."
    EXPOSED_DOCKER_PORTS=()
    while IFS= read -r line; do
        if [[ -n "${line}" ]]; then
            EXPOSED_DOCKER_PORTS+=("${line}")
        fi
    done < <(docker ps --format '{{.Names}} (Port: {{.Ports}})' 2>/dev/null | grep -E "0\.0\.0\.0:[0-9]+|\[::\]:[0-9]+" || true)

    if [[ ${#EXPOSED_DOCKER_PORTS[@]} -gt 0 ]]; then
        echo ""
        warn "   [!] Terdeteksi port container Docker terbuka langsung ke publik:"
        for cp in "${EXPOSED_DOCKER_PORTS[@]}"; do
            echo -e "       \e[1;33m• ${cp}\e[0m"
        done
        echo ""
        info "   Catatan Keamanan:"
        info "   Docker secara bawaan membypass firewall standar (UFW) sehingga port di atas"
        info "   dapat diakses langsung dari internet tanpa melewati WAF Apache/Nginx."
        echo ""
        
        # Mode interaktif jika dijalankan di terminal tty
        USER_CHOICE="1"
        if [[ -t 0 ]]; then
            echo -e "\e[1;36mPilihan Tindakan Pengamanan:\e[0m"
            echo "  [1] Kunci port Docker via rantai DOCKER-USER (Hanya izinkan akses lokal & subnet privat) [DIREKOMENDASIKAN]"
            echo "  [2] Lewati (Biarkan terbuka seperti sekarang)"
            read -r -p "Pilihan Anda [1/2] (default: 1): " INPUT_CHOICE || true
            [[ -n "${INPUT_CHOICE}" ]] && USER_CHOICE="${INPUT_CHOICE}"
        else
            info "   Mode non-interaktif terdeteksi: menerapkan pengamanan default [1] (DOCKER-USER chain lock)."
        fi

        if [[ "${USER_CHOICE}" == "1" ]]; then
            info "   Menerapkan aturan rantai DOCKER-USER di firewall..."
            if command -v iptables >/dev/null 2>&1; then
                # Pastikan rantai DOCKER-USER ada (dibuat otomatis oleh Docker)
                if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
                    # Ambil daftar port TCP yang terikat ke 0.0.0.0
                    RAW_PORTS=$(docker ps --format '{{.Ports}}' 2>/dev/null | grep -oE "0\.0\.0\.0:[0-9]+" | cut -d':' -f2 | sort -u || true)
                    for port in ${RAW_PORTS}; do
                        # Jangan kunci port web server standar jika docker kebetulan pakai 80/443
                        if [[ "${port}" != "80" && "${port}" != "443" ]]; then
                            # Cek apakah sudah ada aturan drop sebelumnya
                            if ! iptables -C DOCKER-USER -p tcp --dport "${port}" ! -s 127.0.0.1 -j DROP 2>/dev/null; then
                                iptables -I DOCKER-USER 1 -p tcp --dport "${port}" ! -s 127.0.0.1 -j DROP 2>/dev/null || true
                                ok "   Port ${port} berhasil dikunci dari akses publik (DOCKER-USER DROP)."
                            fi
                        fi
                    done
                fi
            fi
        else
            info "   Pengamanan port Docker dilewati sesuai pilihan."
        fi
    else
        ok "   Seluruh container Docker tertutup atau hanya terikat ke localhost."
    fi
fi

# ------------------------------------------------------------------------------
# 9. Mendaftarkan & Menjalankan Service Systemd
# ------------------------------------------------------------------------------
info "9. Mendaftarkan dan menjalankan service systemd py-simpledefense..."
cp -f "${BASE_DIR}/systemd/py-simpledefense.service" "${SERVICE_DEST}"
chmod 644 "${SERVICE_DEST}"
systemctl daemon-reload
systemctl enable py-simpledefense.service
systemctl restart py-simpledefense.service

ok "Instalasi & Pembaruan py-simpledefense v2.0 Selesai!"
echo ""
echo "Perintah Bermanfaat:"
echo "  - Cek status layanan : sudo systemctl status py-simpledefense"
echo "  - Pantau log real-time: sudo journalctl -u py-simpledefense -f"
echo "  - Edit konfigurasi   : sudo nano ${CONFIG_FILE}"
echo "  - Uji kirim notifikasi: sudo SIMPLEDEFENSE_ENV=${CONFIG_FILE} python3 ${INSTALL_DIR}/csirt_active_defense.py --test-alert"
echo "=================================================================="
