#!/bin/bash
# =============================================================================
# PRÁCTICA 7 — ORQUESTADOR DE INSTALACIÓN HÍBRIDA + SSL/TLS
# Sistema Operativo: AlmaLinux (sin entorno gráfico)
# Servicios: vsftpd (FTPS), Apache, Nginx, Tomcat
# Dominio: www.reprobados.com
#
# Compatible con la Práctica 5 (ftp.sh):
#   FTP_ROOT        = /srv/ftp
#   VIRTUAL_ROOT    = /srv/ftp/virtual
#   VSFTPD_CONF     = /etc/vsftpd/vsftpd.conf
#   VSFTPD_USER_LIST= /etc/vsftpd/user_list
#   VSFTPD_USERCONF = /etc/vsftpd/users
#   Repositorio FTP : /srv/ftp/general/http/Linux/<Servicio>/
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# COLORES (iguales a ftp.sh)
# ─────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

# ─────────────────────────────────────────────────────────────────────────────
# VARIABLES GLOBALES
# ─────────────────────────────────────────────────────────────────────────────
DOMAIN="www.reprobados.com"
CERT_DIR="/etc/ssl/reprobados"

# ── Rutas exactas de la Práctica 5 (ftp.sh) ──────────────────────────────
FTP_ROOT="/srv/ftp"
GENERAL_DIR="$FTP_ROOT/general"
VIRTUAL_ROOT="$FTP_ROOT/virtual"
VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
VSFTPD_USER_LIST="/etc/vsftpd/user_list"
VSFTPD_USERCONF="/etc/vsftpd/users"

# ── Repositorio de instaladores dentro del general (visible a todos los usuarios FTP) ──
# Estructura esperada:
#   /srv/ftp/general/http/Linux/Apache/  → *.rpm  + *.rpm.sha256
#   /srv/ftp/general/http/Linux/Nginx/   → *.rpm  + *.rpm.sha256
#   /srv/ftp/general/http/Linux/Tomcat/  → *.tar.gz + *.tar.gz.sha256
REPO_BASE="$GENERAL_DIR/http/Linux"

# ── Para acceso FTP remoto (cuando el repo está en OTRO servidor) ──────────
FTP_HOST=""
FTP_USER=""
FTP_PASS=""
FTP_REMOTE_BASE="/http/Linux"   # ruta en el servidor FTP remoto

FUENTE=""  # "LOCAL" | "WEB" | "FTP_REMOTO"

LOG_FILE="/var/log/practica7.log"
SUMMARY_FILE="/tmp/practica7_summary.txt"

# ─────────────────────────────────────────────────────────────────────────────
# VERIFICAR ROOT (igual que ftp.sh)
# ─────────────────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: Ejecuta este script como root (ej. sudo bash $0)${NC}"
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# UTILIDADES
# ─────────────────────────────────────────────────────────────────────────────
log()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }
info()   { echo -e "${CYAN}[INFO]${NC}  $*"; log "INFO: $*"; }
ok()     { echo -e "${GREEN}[OK]${NC}    $*"; log "OK: $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC}  $*"; log "WARN: $*"; }
err()    { echo -e "${RED}[ERROR]${NC} $*"; log "ERROR: $*"; }
header() {
    echo -e "\n${CYAN}${BOLD}══════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  $*${NC}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════${NC}\n"
}
add_summary() { echo "$*" >> "$SUMMARY_FILE"; }

# ─────────────────────────────────────────────────────────────────────────────
# SECCIÓN 1: FUENTE DE INSTALACIÓN
# ─────────────────────────────────────────────────────────────────────────────
elegir_fuente() {
    header "FUENTE DE INSTALACIÓN"
    echo -e "  ${BOLD}[1]${NC} WEB          — dnf / yum (repositorios oficiales)"
    echo -e "  ${BOLD}[2]${NC} FTP LOCAL    — repo en ${BOLD}este servidor${NC} (${REPO_BASE})"
    echo -e "  ${BOLD}[3]${NC} FTP REMOTO   — repo en otro servidor FTP (Práctica 5)"
    echo ""
    read -rp "  Selecciona fuente [1/2/3]: " SEL

    case "$SEL" in
        1) FUENTE="WEB";        info "Fuente: WEB (dnf)" ;;
        2) FUENTE="LOCAL";      info "Fuente: FTP LOCAL ($REPO_BASE)"
           _verificar_repo_local ;;
        3) FUENTE="FTP_REMOTO"; info "Fuente: FTP REMOTO"
           _pedir_credenciales_ftp ;;
        *)  warn "Opción inválida. Usando WEB."; FUENTE="WEB" ;;
    esac
}

_verificar_repo_local() {
    if [[ ! -d "$REPO_BASE" ]]; then
        warn "El directorio $REPO_BASE no existe."
        warn "Necesitas la estructura:"
        warn "  $REPO_BASE/{Apache,Nginx,Tomcat}/"
        warn "  con instaladores + archivos .sha256"
        read -rp "  ¿Continuar de todos modos? [S/N]: " CONT
        [[ ! "$CONT" =~ ^[Ss]$ ]] && { err "Abortado."; exit 1; }
    fi
}

_pedir_credenciales_ftp() {
    echo ""
    read -rp "  Host FTP (IP o hostname): " FTP_HOST
    read -rp "  Usuario FTP: "              FTP_USER
    read -rsp "  Contraseña FTP: "          FTP_PASS
    echo ""
    info "Servidor FTP remoto: $FTP_HOST"
}

# ─────────────────────────────────────────────────────────────────────────────
# CLIENTE FTP NO INTERACTIVO
# Usa curl para hablar con vsftpd de la Práctica 5 (puerto 21, pasivo 40000-40100)
# ─────────────────────────────────────────────────────────────────────────────

# Listar contenido de un directorio en el FTP remoto
_ftp_listar() {
    local ruta="$1"
    curl -s --user "${FTP_USER}:${FTP_PASS}" \
         --ftp-pasv \
         "ftp://${FTP_HOST}${ruta}" 2>/dev/null \
    | awk '{print $NF}' \
    | grep -v '^$' || true
}

# Descargar un archivo del FTP remoto
_ftp_descargar() {
    local ruta_remota="$1"
    local destino="$2"
    info "Descargando ftp://${FTP_HOST}${ruta_remota} ..."
    curl -s --user "${FTP_USER}:${FTP_PASS}" \
         --ftp-pasv \
         "ftp://${FTP_HOST}${ruta_remota}" \
         -o "$destino"
    if [[ ! -s "$destino" ]]; then
        err "Descarga fallida o archivo vacío: $destino"
        return 1
    fi
    ok "Descargado: $(basename "$destino") ($(du -sh "$destino" | cut -f1))"
}

# ─────────────────────────────────────────────────────────────────────────────
# SELECCIÓN DE INSTALADOR (local o FTP remoto)
# Exporta: INSTALADOR_PATH
# ─────────────────────────────────────────────────────────────────────────────
seleccionar_instalador() {
    local servicio="$1"
    INSTALADOR_PATH=""

    case "$FUENTE" in
    # ── Repositorio en este mismo servidor (dentro de /general) ──────────
    LOCAL)
        local dir="${REPO_BASE}/${servicio}"
        if [[ ! -d "$dir" ]]; then
            err "Directorio no encontrado: $dir"
            return 1
        fi
        mapfile -t archivos < <(find "$dir" -maxdepth 1 -type f ! -name '*.sha256' | sort | xargs -I{} basename {})
        if [[ ${#archivos[@]} -eq 0 ]]; then
            err "No hay instaladores en $dir"
            return 1
        fi
        echo ""
        echo -e "  ${BOLD}Instaladores disponibles en $dir:${NC}"
        for i in "${!archivos[@]}"; do
            printf "    [%s] %s\n" "$((i+1))" "${archivos[$i]}"
        done
        echo ""
        local sel
        while true; do
            read -rp "  Selecciona número: " sel
            [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#archivos[@]} )) && break
            echo "  Número inválido."
        done
        INSTALADOR_PATH="${dir}/${archivos[$((sel-1))]}"
        ;;

    # ── Repositorio en servidor FTP remoto ──────────────────────────────
    FTP_REMOTO)
        local ruta_dir="${FTP_REMOTE_BASE}/${servicio}/"
        info "Listando ftp://${FTP_HOST}${ruta_dir} ..."
        mapfile -t archivos < <(_ftp_listar "$ruta_dir" | grep -v '\.sha256$' | grep -v '^$')
        if [[ ${#archivos[@]} -eq 0 ]]; then
            err "No se encontraron instaladores en $ruta_dir"
            return 1
        fi
        echo ""
        echo -e "  ${BOLD}Instaladores disponibles en ftp://${FTP_HOST}${ruta_dir}:${NC}"
        for i in "${!archivos[@]}"; do
            printf "    [%s] %s\n" "$((i+1))" "${archivos[$i]}"
        done
        echo ""
        local sel
        while true; do
            read -rp "  Selecciona número: " sel
            [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#archivos[@]} )) && break
            echo "  Número inválido."
        done
        local nombre="${archivos[$((sel-1))]}"
        local tmp_dest="/tmp/${nombre}"

        # Descargar instalador
        _ftp_descargar "${FTP_REMOTE_BASE}/${servicio}/${nombre}" "$tmp_dest" || return 1

        # Verificar integridad (descarga el .sha256 del FTP)
        _verificar_hash "$tmp_dest" \
            "${FTP_REMOTE_BASE}/${servicio}/${nombre}.sha256" \
            "remoto"

        INSTALADOR_PATH="$tmp_dest"
        ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# VERIFICACIÓN DE INTEGRIDAD SHA256
# ─────────────────────────────────────────────────────────────────────────────
# $1 = archivo local a verificar
# $2 = ruta al .sha256 (local o remota)
# $3 = "local" | "remoto"
_verificar_hash() {
    local archivo="$1"
    local sha256_ruta="$2"
    local tipo="$3"
    local tmp_hash="/tmp/$(basename "$archivo").sha256"

    info "Verificando integridad SHA256 de $(basename "$archivo")..."

    if [[ "$tipo" == "local" ]]; then
        if [[ ! -f "$sha256_ruta" ]]; then
            warn "Archivo .sha256 no encontrado: $sha256_ruta — omitiendo verificación."
            add_summary "  Hash: OMITIDO (sin .sha256) — $(basename "$archivo")"
            return 0
        fi
        cp "$sha256_ruta" "$tmp_hash"
    else
        _ftp_descargar "$sha256_ruta" "$tmp_hash" 2>/dev/null || {
            warn "No se pudo descargar el .sha256 — omitiendo verificación."
            add_summary "  Hash: OMITIDO (sin .sha256 en FTP) — $(basename "$archivo")"
            return 0
        }
    fi

    local hash_esperado hash_calculado
    hash_esperado=$(awk '{print $1}' "$tmp_hash" | tr '[:upper:]' '[:lower:]')
    hash_calculado=$(sha256sum "$archivo" | awk '{print $1}')

    if [[ "$hash_calculado" == "$hash_esperado" ]]; then
        ok "Integridad OK — SHA256 coincide."
        add_summary "  Hash: OK — $(basename "$archivo")"
    else
        err "¡FALLO DE INTEGRIDAD! El archivo puede estar corrupto."
        err "  Esperado:  $hash_esperado"
        err "  Calculado: $hash_calculado"
        add_summary "  Hash: FALLO — $(basename "$archivo")"
        read -rp "  ¿Continuar de todos modos? [S/N]: " CONT
        [[ ! "$CONT" =~ ^[Ss]$ ]] && { err "Instalación cancelada."; exit 1; }
    fi
    rm -f "$tmp_hash"
}

# Wrapper para hash local (instalador dentro del repo local)
verificar_hash_local() {
    local instalador="$1"
    _verificar_hash "$instalador" "${instalador}.sha256" "local"
}

# ─────────────────────────────────────────────────────────────────────────────
# SECCIÓN 2: CERTIFICADOS SSL/TLS
# ─────────────────────────────────────────────────────────────────────────────
generar_cert() {
    local servicio="$1"
    local crt="${CERT_DIR}/${servicio}.crt"
    local key="${CERT_DIR}/${servicio}.key"

    mkdir -p "$CERT_DIR"
    chmod 700 "$CERT_DIR"

    info "Generando certificado autofirmado para $servicio ($DOMAIN)..."
    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout "$key" \
        -out    "$crt" \
        -subj "/C=MX/ST=Sinaloa/L=Culiacan/O=Reprobados/OU=${servicio}/CN=${DOMAIN}" \
        2>/dev/null

    chmod 600 "$key"
    chmod 644 "$crt"
    ok "Certificado: $crt"
    ok "Llave:       $key"
}

# ─────────────────────────────────────────────────────────────────────────────
# SECCIÓN 3: SERVICIOS
# ─────────────────────────────────────────────────────────────────────────────

# ── 3.1  APACHE ──────────────────────────────────────────────────────────────
instalar_apache() {
    header "APACHE HTTPD"

    if [[ "$FUENTE" == "WEB" ]]; then
        info "Instalando Apache + mod_ssl desde dnf..."
        dnf install -y httpd mod_ssl >> "$LOG_FILE" 2>&1
    else
        seleccionar_instalador "Apache" || { err "No se pudo obtener instalador Apache."; return 1; }
        [[ "$FUENTE" == "LOCAL" ]] && verificar_hash_local "$INSTALADOR_PATH"

        info "Instalando desde: $INSTALADOR_PATH"
        if [[ "$INSTALADOR_PATH" == *.rpm ]]; then
            dnf localinstall -y "$INSTALADOR_PATH" >> "$LOG_FILE" 2>&1
        else
            err "Formato no reconocido (se espera .rpm): $INSTALADOR_PATH"; return 1
        fi
        dnf install -y mod_ssl >> "$LOG_FILE" 2>&1 || true
    fi

    systemctl enable --now httpd >> "$LOG_FILE" 2>&1
    ok "Apache instalado e iniciado."

    read -rp "  ¿Activar SSL en Apache? [S/N]: " SSL_OPT
    if [[ "$SSL_OPT" =~ ^[Ss]$ ]]; then
        generar_cert "apache"
        _conf_apache_ssl
        add_summary "Apache: SSL ACTIVADO (443) CN=${DOMAIN}"
    else
        add_summary "Apache: SSL no activado"
    fi
}

_conf_apache_ssl() {
    local CONF="/etc/httpd/conf.d/p7_ssl.conf"
    local CRT="${CERT_DIR}/apache.crt"
    local KEY="${CERT_DIR}/apache.key"

    cat > "$CONF" <<APACHECONF
# Práctica 7: Redirección HTTP→HTTPS + HSTS
<VirtualHost *:80>
    ServerName ${DOMAIN}
    RewriteEngine On
    RewriteRule ^(.*)$ https://%{HTTP_HOST}\$1 [R=301,L]
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>

<VirtualHost *:443>
    ServerName ${DOMAIN}
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile    ${CRT}
    SSLCertificateKeyFile ${KEY}
    SSLProtocol           all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite        HIGH:!aNULL:!MD5

    Header always set Strict-Transport-Security "max-age=31536000"

    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
APACHECONF

    firewall-cmd --permanent --add-service={http,https} >> "$LOG_FILE" 2>&1 || true
    firewall-cmd --reload >> "$LOG_FILE" 2>&1 || true
    systemctl restart httpd >> "$LOG_FILE" 2>&1
    ok "Apache: SSL configurado (443) con HSTS y redirección HTTP→HTTPS."
}

# ── 3.2  NGINX ───────────────────────────────────────────────────────────────
instalar_nginx() {
    header "NGINX"

    if [[ "$FUENTE" == "WEB" ]]; then
        info "Instalando Nginx desde dnf..."
        dnf install -y nginx >> "$LOG_FILE" 2>&1
    else
        seleccionar_instalador "Nginx" || { err "No se pudo obtener instalador Nginx."; return 1; }
        [[ "$FUENTE" == "LOCAL" ]] && verificar_hash_local "$INSTALADOR_PATH"

        dnf localinstall -y "$INSTALADOR_PATH" >> "$LOG_FILE" 2>&1
    fi

    systemctl enable --now nginx >> "$LOG_FILE" 2>&1
    ok "Nginx instalado e iniciado."

    read -rp "  ¿Activar SSL en Nginx? [S/N]: " SSL_OPT
    if [[ "$SSL_OPT" =~ ^[Ss]$ ]]; then
        generar_cert "nginx"
        _conf_nginx_ssl
        add_summary "Nginx: SSL ACTIVADO (443) CN=${DOMAIN}"
    else
        add_summary "Nginx: SSL no activado"
    fi
}

_conf_nginx_ssl() {
    local CONF="/etc/nginx/conf.d/p7_ssl.conf"
    local CRT="${CERT_DIR}/nginx.crt"
    local KEY="${CERT_DIR}/nginx.key"

    # Deshabilitar default.conf para evitar conflicto en puerto 80
    [[ -f /etc/nginx/conf.d/default.conf ]] && \
        mv /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf.p7bak 2>/dev/null || true

    cat > "$CONF" <<NGINXCONF
# Práctica 7: Redirección HTTP→HTTPS + HSTS
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}

server {
    listen 443 ssl;
    server_name ${DOMAIN};

    ssl_certificate     ${CRT};
    ssl_certificate_key ${KEY};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    add_header Strict-Transport-Security "max-age=31536000" always;

    root  /usr/share/nginx/html;
    index index.html;
}
NGINXCONF

    firewall-cmd --permanent --add-service={http,https} >> "$LOG_FILE" 2>&1 || true
    firewall-cmd --reload >> "$LOG_FILE" 2>&1 || true
    nginx -t >> "$LOG_FILE" 2>&1 && systemctl restart nginx >> "$LOG_FILE" 2>&1
    ok "Nginx: SSL configurado (443) con HSTS y redirección HTTP→HTTPS."
}

# ── 3.3  TOMCAT ──────────────────────────────────────────────────────────────
instalar_tomcat() {
    header "APACHE TOMCAT"

    if [[ "$FUENTE" == "WEB" ]]; then
        info "Instalando Java desde dnf..."
        dnf install -y java-17-openjdk-headless >> "$LOG_FILE" 2>&1 || \
        dnf install -y java-11-openjdk-headless >> "$LOG_FILE" 2>&1 || true

        local VER="10.1.24"
        local URL="https://dlcdn.apache.org/tomcat/tomcat-10/v${VER}/bin/apache-tomcat-${VER}.tar.gz"
        info "Descargando Tomcat $VER desde Apache.org..."
        curl -sL "$URL" -o /tmp/tomcat.tar.gz >> "$LOG_FILE" 2>&1 || {
            err "No se pudo descargar Tomcat. Usa la fuente LOCAL o FTP."; return 1
        }
        tar -xzf /tmp/tomcat.tar.gz -C /opt/ >> "$LOG_FILE" 2>&1
    else
        seleccionar_instalador "Tomcat" || { err "No se pudo obtener instalador Tomcat."; return 1; }
        [[ "$FUENTE" == "LOCAL" ]] && verificar_hash_local "$INSTALADOR_PATH"

        dnf install -y java-17-openjdk-headless >> "$LOG_FILE" 2>&1 || \
        dnf install -y java-11-openjdk-headless >> "$LOG_FILE" 2>&1 || true

        if [[ "$INSTALADOR_PATH" == *.tar.gz ]]; then
            tar -xzf "$INSTALADOR_PATH" -C /opt/ >> "$LOG_FILE" 2>&1
        else
            err "Formato no reconocido (se espera .tar.gz): $INSTALADOR_PATH"; return 1
        fi
    fi

    local TOMCAT_DIR
    TOMCAT_DIR=$(find /opt -maxdepth 1 -name 'apache-tomcat-*' -type d | sort -V | tail -1)
    if [[ -z "$TOMCAT_DIR" ]]; then
        err "No se encontró el directorio de Tomcat en /opt/"; return 1
    fi
    ln -sfn "$TOMCAT_DIR" /opt/tomcat
    chmod +x /opt/tomcat/bin/*.sh

    # Usuario de sistema para Tomcat
    id tomcat &>/dev/null || useradd -r -d /opt/tomcat -s /sbin/nologin tomcat
    chown -R tomcat:tomcat /opt/tomcat

    # Servicio systemd
    cat > /etc/systemd/system/tomcat.service <<TOMCATSVC
[Unit]
Description=Apache Tomcat
After=network.target

[Service]
Type=forking
User=tomcat
Group=tomcat
Environment="JAVA_HOME=/usr"
Environment="CATALINA_HOME=/opt/tomcat"
Environment="CATALINA_BASE=/opt/tomcat"
Environment="CATALINA_PID=/opt/tomcat/temp/tomcat.pid"
ExecStart=/opt/tomcat/bin/startup.sh
ExecStop=/opt/tomcat/bin/shutdown.sh
UMask=0007
RestartSec=10
Restart=always

[Install]
WantedBy=multi-user.target
TOMCATSVC

    systemctl daemon-reload
    systemctl enable --now tomcat >> "$LOG_FILE" 2>&1
    ok "Tomcat instalado en $TOMCAT_DIR (enlace: /opt/tomcat)"

    read -rp "  ¿Activar SSL en Tomcat (puerto 8443)? [S/N]: " SSL_OPT
    if [[ "$SSL_OPT" =~ ^[Ss]$ ]]; then
        generar_cert "tomcat"
        _conf_tomcat_ssl
        add_summary "Tomcat: SSL ACTIVADO (8443) CN=${DOMAIN}"
    else
        add_summary "Tomcat: SSL no activado (puerto 8080)"
    fi
}

_conf_tomcat_ssl() {
    local CRT="${CERT_DIR}/tomcat.crt"
    local KEY="${CERT_DIR}/tomcat.key"
    local KEYSTORE="/opt/tomcat/conf/keystore.p12"
    local SERVER_XML="/opt/tomcat/conf/server.xml"

    info "Generando keystore PKCS12 para Tomcat..."
    openssl pkcs12 -export \
        -in  "$CRT" -inkey "$KEY" \
        -out "$KEYSTORE" \
        -name tomcat -passout pass:changeit >> "$LOG_FILE" 2>&1

    chown tomcat:tomcat "$KEYSTORE"
    chmod 640 "$KEYSTORE"

    # Insertar conector HTTPS en server.xml si no existe aún
    if ! grep -q "8443" "$SERVER_XML"; then
        sed -i "s|</Service>|    <Connector port=\"8443\"\n               protocol=\"org.apache.coyote.http11.Http11NioProtocol\"\n               maxThreads=\"150\" SSLEnabled=\"true\"\n               scheme=\"https\" secure=\"true\" clientAuth=\"false\"\n               keystoreFile=\"${KEYSTORE}\"\n               keystorePass=\"changeit\"\n               sslProtocol=\"TLS\" />\n</Service>|" \
            "$SERVER_XML"
    fi

    firewall-cmd --permanent --add-port={8080,8443}/tcp >> "$LOG_FILE" 2>&1 || true
    firewall-cmd --reload >> "$LOG_FILE" 2>&1 || true
    systemctl restart tomcat >> "$LOG_FILE" 2>&1
    ok "Tomcat: SSL configurado en puerto 8443."
}

# ── 3.4  vsftpd — AGREGAR FTPS SOBRE LA PRÁCTICA 5 ──────────────────────────
# IMPORTANTE: NO reinstala vsftpd ni toca usuarios/estructuras virtuales.
# Solo agrega el bloque SSL al vsftpd.conf existente de la Práctica 5.
configurar_vsftpd_ssl() {
    header "vsftpd — Activar FTPS (SSL/TLS)"

    # Verificar que la Práctica 5 ya instaló vsftpd
    if ! rpm -q vsftpd &>/dev/null; then
        err "vsftpd no está instalado. Ejecuta primero ftp.sh (Opción 1 del menú)."
        add_summary "vsftpd: FTPS NO configurado — vsftpd no instalado"
        return 1
    fi

    if [[ ! -f "$VSFTPD_CONF" ]]; then
        err "No se encontró $VSFTPD_CONF. Ejecuta primero ftp.sh."
        add_summary "vsftpd: FTPS NO configurado — sin vsftpd.conf"
        return 1
    fi

    read -rp "  ¿Activar SSL/TLS (FTPS implícito, puerto 990) en vsftpd? [S/N]: " SSL_OPT
    if [[ ! "$SSL_OPT" =~ ^[Ss]$ ]]; then
        add_summary "vsftpd: FTPS no activado"
        return 0
    fi

    generar_cert "vsftpd"

    local CRT="${CERT_DIR}/vsftpd.crt"
    local KEY="${CERT_DIR}/vsftpd.key"

    # Detener vsftpd (igual que en ftp.sh: detener_vsftpd)
    systemctl is-active --quiet vsftpd 2>/dev/null && systemctl stop vsftpd || true
    sleep 1

    # Backup del vsftpd.conf que generó ftp.sh
    cp "$VSFTPD_CONF" "${VSFTPD_CONF}.p7bak.$(date +%s)"

    # Eliminar cualquier directiva SSL previa (idempotente)
    sed -i \
        -e '/^ssl_enable/d'           \
        -e '/^implicit_ssl/d'         \
        -e '/^listen_port/d'          \
        -e '/^allow_anon_ssl/d'       \
        -e '/^force_local_data_ssl/d' \
        -e '/^force_local_logins_ssl/d' \
        -e '/^ssl_tlsv1/d'            \
        -e '/^ssl_sslv2/d'            \
        -e '/^ssl_sslv3/d'            \
        -e '/^require_ssl_reuse/d'    \
        -e '/^ssl_ciphers/d'          \
        -e '/^rsa_cert_file/d'        \
        -e '/^rsa_private_key_file/d' \
        "$VSFTPD_CONF"

    # Agregar bloque SSL al final del vsftpd.conf existente
    cat >> "$VSFTPD_CONF" <<FTPSSL

# ── Práctica 7: FTPS implícito (SSL/TLS) ─────────────────────────────────
ssl_enable=YES
implicit_ssl=YES
listen_port=990
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
ssl_ciphers=HIGH
rsa_cert_file=${CRT}
rsa_private_key_file=${KEY}
FTPSSL

    # Firewall: agregar puerto 990 (los puertos 40000-40100 ya los abrió ftp.sh)
    if systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port=990/tcp >> "$LOG_FILE" 2>&1 || true
        firewall-cmd --reload >> "$LOG_FILE" 2>&1 || true
    fi

    # SELinux: contexto correcto para los certificados
    if command -v getenforce &>/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
        chcon -t cert_t "$CRT" "$KEY" 2>/dev/null || true
        setsebool -P ftpd_use_passive_mode on >> "$LOG_FILE" 2>&1 || true
    fi

    systemctl start vsftpd >> "$LOG_FILE" 2>&1
    ok "vsftpd: FTPS implícito activado en puerto 990."
    ok "Los usuarios/grupos de la Práctica 5 siguen intactos."
    add_summary "vsftpd: FTPS ACTIVADO (990) CN=${DOMAIN}"
}

# ─────────────────────────────────────────────────────────────────────────────
# SECCIÓN 4: VERIFICACIÓN AUTOMATIZADA
# ─────────────────────────────────────────────────────────────────────────────
verificar_todo() {
    header "VERIFICACIÓN AUTOMATIZADA"
    add_summary ""
    add_summary "╔══════════════════════════════════════════════════════════════╗"
    add_summary "  RESUMEN PRÁCTICA 7 — $(date '+%Y-%m-%d %H:%M:%S')"
    add_summary "  Dominio: ${DOMAIN}"
    add_summary "╚══════════════════════════════════════════════════════════════╝"

    # ── Apache ──
    echo -e "\n${CYAN}[Apache]${NC}"
    if systemctl is-active --quiet httpd 2>/dev/null; then
        ok "httpd: ACTIVO"; add_summary "[OK] Apache: activo"
        if ss -tlnp | grep -q ':443'; then
            ok "Puerto 443: escuchando"; add_summary "[OK] Apache: puerto 443 activo"
            local resp
            resp=$(curl -sk -o /dev/null -w "%{http_code}" "https://127.0.0.1/" 2>/dev/null || echo "ERR")
            info "HTTPS responde: HTTP $resp"; add_summary "     Apache: HTTPS responde HTTP $resp"
            local redir
            redir=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1/" 2>/dev/null || echo "ERR")
            info "HTTP→HTTPS redir: $redir"; add_summary "     Apache: HTTP→HTTPS redir $redir"
            if [[ -f "${CERT_DIR}/apache.crt" ]]; then
                local cn; cn=$(openssl x509 -noout -subject -in "${CERT_DIR}/apache.crt" 2>/dev/null | sed 's/.*CN=//')
                ok "CN del certificado: $cn"; add_summary "     Apache: CN=${cn}"
            fi
        else
            warn "Puerto 443: NO activo"; add_summary "[--] Apache: puerto 443 no activo"
        fi
    else
        warn "httpd: INACTIVO"; add_summary "[--] Apache: no activo"
    fi

    # ── Nginx ──
    echo -e "\n${CYAN}[Nginx]${NC}"
    if systemctl is-active --quiet nginx 2>/dev/null; then
        ok "nginx: ACTIVO"; add_summary "[OK] Nginx: activo"
        if ss -tlnp | grep -q ':443'; then
            ok "Puerto 443: escuchando"; add_summary "[OK] Nginx: puerto 443 activo"
            local resp
            resp=$(curl -sk -o /dev/null -w "%{http_code}" "https://127.0.0.1/" 2>/dev/null || echo "ERR")
            info "HTTPS responde: HTTP $resp"; add_summary "     Nginx: HTTPS responde HTTP $resp"
            if [[ -f "${CERT_DIR}/nginx.crt" ]]; then
                local cn; cn=$(openssl x509 -noout -subject -in "${CERT_DIR}/nginx.crt" 2>/dev/null | sed 's/.*CN=//')
                ok "CN del certificado: $cn"; add_summary "     Nginx: CN=${cn}"
            fi
        else
            warn "Puerto 443: NO activo"; add_summary "[--] Nginx: puerto 443 no activo"
        fi
    else
        warn "nginx: INACTIVO"; add_summary "[--] Nginx: no activo"
    fi

    # ── Tomcat ──
    echo -e "\n${CYAN}[Tomcat]${NC}"
    if systemctl is-active --quiet tomcat 2>/dev/null; then
        ok "tomcat: ACTIVO"; add_summary "[OK] Tomcat: activo"
    else
        warn "tomcat: INACTIVO (puede tardar ~30s en arrancar)"; add_summary "[--] Tomcat: no activo"
    fi
    if ss -tlnp 2>/dev/null | grep -q ':8443'; then
        ok "Puerto 8443: escuchando"; add_summary "[OK] Tomcat: puerto 8443 activo"
        local resp
        resp=$(curl -sk -o /dev/null -w "%{http_code}" "https://127.0.0.1:8443/" 2>/dev/null || echo "ERR")
        info "HTTPS :8443 responde: HTTP $resp"; add_summary "     Tomcat: HTTPS responde HTTP $resp"
        if [[ -f "${CERT_DIR}/tomcat.crt" ]]; then
            local cn; cn=$(openssl x509 -noout -subject -in "${CERT_DIR}/tomcat.crt" 2>/dev/null | sed 's/.*CN=//')
            ok "CN del certificado: $cn"; add_summary "     Tomcat: CN=${cn}"
        fi
    elif ss -tlnp 2>/dev/null | grep -q ':8080'; then
        ok "Puerto 8080: escuchando (sin SSL)"; add_summary "[OK] Tomcat: puerto 8080 (sin SSL)"
    else
        warn "Tomcat: ningún puerto detectado aún"; add_summary "[--] Tomcat: sin puerto activo"
    fi

    # ── vsftpd / FTPS ──
    echo -e "\n${CYAN}[vsftpd / FTPS]${NC}"
    if systemctl is-active --quiet vsftpd 2>/dev/null; then
        ok "vsftpd: ACTIVO"; add_summary "[OK] vsftpd: activo"
        if ss -tlnp 2>/dev/null | grep -q ':990'; then
            ok "Puerto 990 (FTPS implícito): escuchando"
            add_summary "[OK] vsftpd: puerto 990 FTPS activo"
        elif ss -tlnp 2>/dev/null | grep -q ':21'; then
            info "Puerto 21 (FTP sin SSL): escuchando"
            add_summary "[OK] vsftpd: puerto 21 FTP activo (sin SSL)"
        fi
        if [[ -f "${CERT_DIR}/vsftpd.crt" ]]; then
            local cn; cn=$(openssl x509 -noout -subject -in "${CERT_DIR}/vsftpd.crt" 2>/dev/null | sed 's/.*CN=//')
            ok "CN del certificado: $cn"; add_summary "     vsftpd: CN=${cn}"
        fi
        # Mostrar usuarios de la Práctica 5 que siguen activos
        if [[ -f "$VSFTPD_USER_LIST" ]]; then
            local total; total=$(grep -vc '^anonymous$' "$VSFTPD_USER_LIST" 2>/dev/null || echo 0)
            info "Usuarios FTP de Práctica 5: $total activos"
            add_summary "     vsftpd: $total usuario(s) Práctica 5 conservados"
        fi
    else
        warn "vsftpd: INACTIVO"; add_summary "[--] vsftpd: no activo"
    fi

    # ── Resumen de certificados generados ──
    echo -e "\n${CYAN}[Certificados en ${CERT_DIR}]${NC}"
    if [[ -d "$CERT_DIR" ]]; then
        local found=0
        for crt in "${CERT_DIR}"/*.crt; do
            [[ -f "$crt" ]] || continue
            local nombre; nombre=$(basename "$crt" .crt)
            local exp; exp=$(openssl x509 -noout -enddate -in "$crt" 2>/dev/null | cut -d= -f2)
            ok "  $nombre — expira: $exp"
            add_summary "     Cert $nombre: expira $exp"
            found=1
        done
        [[ $found -eq 0 ]] && warn "No hay certificados generados aún."
    else
        warn "Directorio $CERT_DIR no encontrado"
    fi

    add_summary ""
    add_summary "  Log completo: $LOG_FILE"
}

# ─────────────────────────────────────────────────────────────────────────────
# MENÚ PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────
mostrar_resumen() {
    header "RESUMEN FINAL"
    cat "$SUMMARY_FILE"
    echo ""
    info "Log:     $LOG_FILE"
    info "Resumen: $SUMMARY_FILE"
    echo ""; read -rp "Presiona Enter para continuar..."
}

while true; do
    clear
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║      PRÁCTICA 7 — SSL/TLS — AlmaLinux            ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"

    # Estado de servicios
    echo ""
    for svc in httpd nginx tomcat vsftpd; do
        systemctl is-active --quiet "$svc" 2>/dev/null \
            && echo -e "  $svc: ${GREEN}activo${NC}" \
            || echo -e "  $svc: ${RED}inactivo${NC}"
    done
    echo ""

    echo -e "  ${BOLD}${CYAN}1)${NC} Apache"
    echo -e "  ${BOLD}${CYAN}2)${NC} Nginx"
    echo -e "  ${BOLD}${CYAN}3)${NC} Tomcat"
    echo -e "  ${BOLD}${CYAN}4)${NC} vsftpd — Activar FTPS ${YELLOW}(requiere Práctica 5 instalada)${NC}"
    echo -e "  ${BOLD}${CYAN}5)${NC} TODOS los servicios"
    echo -e "  ${BOLD}${CYAN}6)${NC} Solo verificar instalaciones existentes"
    echo -e "  ${BOLD}${CYAN}7)${NC} Salir"
    echo ""
    read -rp "  Elige opción [1-7]: " OPCION

    > "$SUMMARY_FILE"
    touch "$LOG_FILE"
    log "=== Práctica 7 — opción $OPCION ==="

    case "$OPCION" in
        1|2|3|5)
            elegir_fuente
            case "$OPCION" in
                1) instalar_apache ;;
                2) instalar_nginx ;;
                3) instalar_tomcat ;;
                5) instalar_apache
                   instalar_nginx
                   instalar_tomcat
                   configurar_vsftpd_ssl ;;
            esac
            verificar_todo
            mostrar_resumen
            ;;
        4)
            configurar_vsftpd_ssl
            verificar_todo
            mostrar_resumen
            ;;
        6)
            verificar_todo
            mostrar_resumen
            ;;
        7) echo "Saliendo..."; exit 0 ;;
        *) echo "Opción no válida."; sleep 1 ;;
    esac
done