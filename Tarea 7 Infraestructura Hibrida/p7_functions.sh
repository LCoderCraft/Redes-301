#!/bin/bash
# ============================================================
# p7_functions.sh - Funciones Práctica 7 | AlmaLinux
# SSL/TLS para Apache, Nginx, Tomcat, vsftpd
# Cliente FTP dinámico + validación de integridad SHA256
# ============================================================

# ── COLORES ──────────────────────────────────────────────────
RED='\033[0;31m';    GREEN='\033[0;32m';   YELLOW='\033[1;33m'
BLUE='\033[0;34m';   CYAN='\033[0;36m';    MAGENTA='\033[0;35m'
NC='\033[0m';        BOLD='\033[1m'

# ── CONSTANTES ───────────────────────────────────────────────
DOMAIN="www.reprobados.com"
SSL_DIR="/etc/ssl/reprobados"
CERT_FILE="$SSL_DIR/reprobados.crt"
KEY_FILE="$SSL_DIR/reprobados.key"
FTP_HOST=""           # Se pide al usuario si elige FTP
FTP_USER=""
FTP_PASS=""

PUERTOS_RESERVADOS=(20 21 22 23 25 53 67 68 69 110 111 123 135
                    137 138 139 143 161 162 389 445 465 500 514
                    587 636 993 995 1433 1521 2049 3306 3389 5432
                    5900)

# ============================================================
# UTILIDADES GENERALES
# ============================================================

function verificar_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}${BOLD}[-] Debes ejecutar este script como root.${NC}"
        exit 1
    fi
    echo -e "${BLUE}[*] Verificando dependencias del sistema...${NC}"
    dnf install -y -q openssl curl wget policycoreutils-python-utils \
        bind-utils mod_ssl &>/dev/null
}

function puerto_es_reservado() {
    local p=$1
    for r in "${PUERTOS_RESERVADOS[@]}"; do [ "$p" -eq "$r" ] && return 0; done
    return 1
}

function puerto_en_uso() { ss -tlnp 2>/dev/null | grep -q ":$1 "; }

function pedir_puerto() {
    local etiqueta="${1:-HTTP}"
    while true; do
        read -p $'\e[1;33mPuerto para '"$etiqueta"' (ej. 8080): \e[0m' PUERTO_SELECCIONADO
        [[ ! "$PUERTO_SELECCIONADO" =~ ^[0-9]+$ ]] && { echo -e "${RED}[!] Debe ser numérico.${NC}"; continue; }
        [ "$PUERTO_SELECCIONADO" -lt 1 ] || [ "$PUERTO_SELECCIONADO" -gt 65535 ] && \
            { echo -e "${RED}[!] Fuera de rango (1-65535).${NC}"; continue; }
        puerto_es_reservado "$PUERTO_SELECCIONADO" && \
            { echo -e "${RED}[!] Puerto reservado para otro servicio crítico.${NC}"; continue; }
        puerto_en_uso "$PUERTO_SELECCIONADO" && \
            { echo -e "${RED}[!] Puerto $PUERTO_SELECCIONADO ya en uso.${NC}"; continue; }
        break
    done
}

function configurar_firewall() {
    local puerto=$1
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port="${puerto}/tcp" &>/dev/null
        firewall-cmd --reload &>/dev/null
        echo -e "${BLUE}[*] Firewall: puerto $puerto habilitado.${NC}"
    fi
    if command -v semanage &>/dev/null; then
        semanage port -a -t http_port_t -p tcp "$puerto" 2>/dev/null || \
        semanage port -m -t http_port_t -p tcp "$puerto" 2>/dev/null
    fi
}

function crear_index() {
    local dir=$1 srv=$2 ver=$3 puerto=$4 ssl=${5:-no}
    mkdir -p "$dir"
    local proto="HTTP"; [ "$ssl" = "yes" ] && proto="HTTPS (SSL/TLS)"
    cat > "$dir/index.html" << HTML
<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<title>${srv}</title>
<style>body{font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9;
display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;
padding:40px 60px;text-align:center}h1{color:#58a6ff}
span{color:#3fb950;font-weight:bold}.ssl{color:#f0883e}</style>
</head><body><div class="card">
<h1>Servidor Web Activo</h1>
<p>Servidor: <span>${srv}</span></p>
<p>Versión: <span>${ver}</span></p>
<p>Puerto: <span>${puerto}</span></p>
<p>Protocolo: <span class="ssl">${proto}</span></p>
<p>Dominio: <span>${DOMAIN}</span></p>
<hr style="border-color:#30363d;margin:20px 0">
<small>Infraestructura SSL/TLS - Práctica 7</small>
</div></body></html>
HTML
    chmod 644 "$dir/index.html"
}

# ============================================================
# GENERACIÓN DE CERTIFICADO SSL (AUTOFIRMADO)
# ============================================================

function generar_certificado_ssl() {
    echo -e "${BLUE}[*] Generando certificado SSL autofirmado para ${DOMAIN}...${NC}"
    mkdir -p "$SSL_DIR"
    chmod 700 "$SSL_DIR"

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY_FILE" \
        -out    "$CERT_FILE" \
        -subj   "/C=MX/ST=Sinaloa/L=Culiacan/O=Reprobados/OU=TI/CN=${DOMAIN}" \
        -addext "subjectAltName=DNS:${DOMAIN},DNS:reprobados.com,IP:$(hostname -I | awk '{print $1}')" \
        2>/dev/null

    chmod 600 "$KEY_FILE"
    chmod 644 "$CERT_FILE"
    echo -e "${GREEN}[+] Certificado generado: $CERT_FILE${NC}"
    echo -e "${GREEN}[+] Llave privada:        $KEY_FILE${NC}"
}

function verificar_o_generar_cert() {
    if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
        local exp
        exp=$(openssl x509 -noout -enddate -in "$CERT_FILE" 2>/dev/null | cut -d= -f2)
        echo -e "${YELLOW}[!] Ya existe un certificado (expira: $exp).${NC}"
        read -p $'\e[1;33m¿Regenerar certificado? [s/N]: \e[0m' regen
        [[ "$regen" =~ ^[sS]$ ]] && generar_certificado_ssl
    else
        generar_certificado_ssl
    fi
}

# ============================================================
# CLIENTE FTP DINÁMICO
# ============================================================

function configurar_ftp_origen() {
    echo -e "${CYAN}--- Configuración del servidor FTP privado ---${NC}"
    read -p $'\e[1;33mIP del servidor FTP: \e[0m' FTP_HOST
    read -p $'\e[1;33mUsuario FTP: \e[0m' FTP_USER
    read -s -p $'\e[1;33mContraseña FTP: \e[0m' FTP_PASS
    echo ""
}

# Lista carpetas en una ruta FTP y devuelve array
function ftp_listar_directorios() {
    local ruta=$1
    curl -s --list-only \
         -u "${FTP_USER}:${FTP_PASS}" \
         "ftp://${FTP_HOST}${ruta}" 2>/dev/null \
    | grep -v '^\.' | sort
}

# Lista archivos (no directorios) en ruta FTP
function ftp_listar_archivos() {
    local ruta=$1
    curl -s --list-only \
         -u "${FTP_USER}:${FTP_PASS}" \
         "ftp://${FTP_HOST}${ruta}" 2>/dev/null \
    | grep -v '/$' | grep '\.' | sort
}

# Descarga un archivo desde FTP
function ftp_descargar() {
    local ruta_remota=$1 destino=$2
    echo -e "${BLUE}[*] Descargando: ftp://${FTP_HOST}${ruta_remota}${NC}"
    curl -# -u "${FTP_USER}:${FTP_PASS}" \
         "ftp://${FTP_HOST}${ruta_remota}" \
         -o "$destino" 2>&1
    return $?
}

# Navega FTP y permite elegir un instalador; devuelve $ARCHIVO_SELECCIONADO y $RUTA_FTP_ARCHIVO
function navegar_ftp_y_seleccionar() {
    local os_dir="/http/Linux"  # Base del repositorio para Linux

    echo -e "${CYAN}--- Navegando repositorio FTP: ${FTP_HOST}${os_dir} ---${NC}"

    # 1. Listar servicios disponibles
    mapfile -t SERVICIOS < <(ftp_listar_directorios "${os_dir}/")
    if [ ${#SERVICIOS[@]} -eq 0 ]; then
        echo -e "${RED}[-] No se encontraron servicios en ${os_dir}/. Verifica conexión FTP.${NC}"
        return 1
    fi

    echo -e "\n${CYAN}Servicios disponibles en el repositorio:${NC}"
    for i in "${!SERVICIOS[@]}"; do
        echo -e "  $((i+1)). ${SERVICIOS[$i]}"
    done

    local sel_srv=""
    while true; do
        read -p $'\e[1;33mSelecciona servicio [1-'"${#SERVICIOS[@]}"']: \e[0m' sel_srv
        [[ "$sel_srv" =~ ^[0-9]+$ ]] && \
        [ "$sel_srv" -ge 1 ] && [ "$sel_srv" -le "${#SERVICIOS[@]}" ] && break
        echo -e "${RED}[!] Selección inválida.${NC}"
    done
    local servicio="${SERVICIOS[$((sel_srv-1))]}"
    local ruta_srv="${os_dir}/${servicio}"

    # 2. Listar archivos en la carpeta del servicio
    mapfile -t ARCHIVOS < <(ftp_listar_archivos "${ruta_srv}/")
    # Filtrar solo los instaladores (excluir .sha256 y .md5)
    mapfile -t INSTALADORES < <(printf '%s\n' "${ARCHIVOS[@]}" | grep -v '\.sha256$' | grep -v '\.md5$')

    if [ ${#INSTALADORES[@]} -eq 0 ]; then
        echo -e "${RED}[-] No se encontraron instaladores en ${ruta_srv}/.${NC}"
        return 1
    fi

    echo -e "\n${CYAN}Instaladores disponibles para ${servicio}:${NC}"
    for i in "${!INSTALADORES[@]}"; do
        echo -e "  $((i+1)). ${INSTALADORES[$i]}"
    done

    local sel_pkg=""
    while true; do
        read -p $'\e[1;33mSelecciona versión [1-'"${#INSTALADORES[@]}"']: \e[0m' sel_pkg
        [[ "$sel_pkg" =~ ^[0-9]+$ ]] && \
        [ "$sel_pkg" -ge 1 ] && [ "$sel_pkg" -le "${#INSTALADORES[@]}" ] && break
        echo -e "${RED}[!] Selección inválida.${NC}"
    done

    ARCHIVO_SELECCIONADO="${INSTALADORES[$((sel_pkg-1))]}"
    RUTA_FTP_ARCHIVO="${ruta_srv}/${ARCHIVO_SELECCIONADO}"
    RUTA_FTP_SERVICIO="$ruta_srv"
    echo -e "${GREEN}[+] Archivo seleccionado: $ARCHIVO_SELECCIONADO${NC}"
}

# Descarga y valida hash SHA256 de un instalador FTP
function descargar_y_validar_hash() {
    local ruta_remota=$1    # ej: /http/Linux/Apache/apache_2.4.deb
    local destino=$2        # ruta local de destino
    local nombre_archivo
    nombre_archivo=$(basename "$ruta_remota")
    local ruta_dir
    ruta_dir=$(dirname "$ruta_remota")

    # Descargar instalador
    if ! ftp_descargar "$ruta_remota" "$destino"; then
        echo -e "${RED}[-] Error al descargar $nombre_archivo.${NC}"
        return 1
    fi

    # Buscar archivo hash (.sha256 preferido, luego .md5)
    local hash_remoto="" hash_file="" hash_tipo=""
    if ftp_listar_archivos "${ruta_dir}/" | grep -q "${nombre_archivo}.sha256"; then
        hash_file="${ruta_dir}/${nombre_archivo}.sha256"
        hash_tipo="sha256"
    elif ftp_listar_archivos "${ruta_dir}/" | grep -q "${nombre_archivo}.md5"; then
        hash_file="${ruta_dir}/${nombre_archivo}.md5"
        hash_tipo="md5"
    fi

    if [ -z "$hash_file" ]; then
        echo -e "${YELLOW}[!] No se encontró archivo de hash para $nombre_archivo. Se omite verificación.${NC}"
        return 0
    fi

    local hash_tmp="/tmp/${nombre_archivo}.hash"
    echo -e "${BLUE}[*] Descargando hash ${hash_tipo^^}: ${hash_file}${NC}"
    ftp_descargar "$hash_file" "$hash_tmp" &>/dev/null

    # Calcular hash local
    local hash_local hash_esperado
    if [ "$hash_tipo" = "sha256" ]; then
        hash_local=$(sha256sum "$destino" | awk '{print $1}')
    else
        hash_local=$(md5sum "$destino" | awk '{print $1}')
    fi

    hash_esperado=$(awk '{print $1}' "$hash_tmp" 2>/dev/null)
    rm -f "$hash_tmp"

    echo -e "${BLUE}[*] Hash esperado:  $hash_esperado${NC}"
    echo -e "${BLUE}[*] Hash calculado: $hash_local${NC}"

    if [ "$hash_local" = "$hash_esperado" ]; then
        echo -e "${GREEN}${BOLD}[+] ✓ Integridad verificada: el archivo no fue corrompido.${NC}"
        return 0
    else
        echo -e "${RED}${BOLD}[-] ✗ INTEGRIDAD FALLIDA: el archivo está corrompido o fue alterado.${NC}"
        rm -f "$destino"
        return 1
    fi
}

# ============================================================
# ELEGIR ORIGEN: WEB o FTP
# ============================================================

function elegir_origen() {
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│  Fuente de instalación               │${NC}"
    echo -e "${CYAN}│  1. WEB  (gestor de paquetes/dnf)   │${NC}"
    echo -e "${CYAN}│  2. FTP  (repositorio privado)       │${NC}"
    echo -e "${CYAN}└─────────────────────────────────────┘${NC}"
    local sel=""
    while true; do
        read -p $'\e[1;33mElige origen [1-2]: \e[0m' sel
        case $sel in
            1) ORIGEN="WEB"; break ;;
            2) ORIGEN="FTP"; configurar_ftp_origen; break ;;
            *) echo -e "${RED}[!] Inválido.${NC}" ;;
        esac
    done
}

# ============================================================
# PREGUNTA SSL
# ============================================================

function preguntar_ssl() {
    read -p $'\e[1;33m¿Desea activar SSL/TLS en este servicio? [S/N]: \e[0m' ACTIVAR_SSL
    [[ "$ACTIVAR_SSL" =~ ^[sS]$ ]] && ACTIVAR_SSL="yes" || ACTIVAR_SSL="no"
}

# ============================================================
# APACHE - INSTALACIÓN + SSL
# ============================================================

function menu_apache() {
    clear
    echo -e "${CYAN}--- Apache httpd - Práctica 7 ---${NC}"
    elegir_origen

    if [ "$ORIGEN" = "FTP" ]; then
        instalar_apache_ftp
    else
        instalar_apache_web
    fi
}

function instalar_apache_web() {
    # Instalar desde repositorio
    if rpm -q httpd &>/dev/null; then
        read -p $'\e[1;33m¿Reinstalar Apache? [s/N]: \e[0m' r
        [[ "$r" =~ ^[sS]$ ]] && { systemctl stop httpd &>/dev/null; dnf remove -y -q httpd &>/dev/null; } || return
    fi

    echo -e "${BLUE}[*] Instalando Apache desde repositorio...${NC}"
    dnf install -y -q httpd mod_ssl &>/dev/null || { echo -e "${RED}[-] Error instalando Apache.${NC}"; read; return 1; }

    _configurar_apache_comun
}

function instalar_apache_ftp() {
    navegar_ftp_y_seleccionar || { read; return 1; }
    local dest="/tmp/${ARCHIVO_SELECCIONADO}"
    descargar_y_validar_hash "$RUTA_FTP_ARCHIVO" "$dest" || { read; return 1; }

    echo -e "${BLUE}[*] Instalando $ARCHIVO_SELECCIONADO desde FTP...${NC}"
    if [[ "$ARCHIVO_SELECCIONADO" == *.rpm ]]; then
        dnf install -y -q "$dest" &>/dev/null
    elif [[ "$ARCHIVO_SELECCIONADO" == *.tar.gz ]]; then
        tar -xzf "$dest" -C /opt/ &>/dev/null
    else
        echo -e "${YELLOW}[!] Formato no reconocido. Intentando con dnf...${NC}"
        dnf install -y -q "$dest" &>/dev/null
    fi
    rm -f "$dest"

    # Asegurarse de que httpd y mod_ssl estén instalados
    dnf install -y -q httpd mod_ssl &>/dev/null

    _configurar_apache_comun
}

function _configurar_apache_comun() {
    preguntar_ssl
    pedir_puerto "HTTP"
    local puerto_http="$PUERTO_SELECCIONADO"

    local ver_real
    ver_real=$(httpd -v 2>/dev/null | grep -oP 'Apache/\K[\d.]+' || echo "desconocida")

    # Config básica
    sed -i "s/^Listen .*/Listen $puerto_http/" /etc/httpd/conf/httpd.conf
    cat > /etc/httpd/conf.d/security.conf << 'EOF'
ServerTokens Prod
ServerSignature Off
TraceEnable Off
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</IfModule>
EOF

    mkdir -p /var/www/html
    crear_index "/var/www/html" "Apache httpd" "$ver_real" "$puerto_http" "$ACTIVAR_SSL"
    chown -R apache:apache /var/www/html
    chmod -R 755 /var/www/html

    if [ "$ACTIVAR_SSL" = "yes" ]; then
        verificar_o_generar_cert
        pedir_puerto "HTTPS"
        local puerto_https="$PUERTO_SELECCIONADO"

        # Habilitar https en firewall/SELinux
        configurar_firewall "$puerto_https"

        cat > /etc/httpd/conf.d/ssl_reprobados.conf << EOF
# --- VirtualHost HTTP → redirección a HTTPS ---
<VirtualHost *:${puerto_http}>
    ServerName ${DOMAIN}
    RewriteEngine On
    RewriteRule ^(.*)$ https://%{HTTP_HOST}:${puerto_https}\$1 [R=301,L]
</VirtualHost>

# --- VirtualHost HTTPS ---
<VirtualHost *:${puerto_https}>
    ServerName ${DOMAIN}
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile    ${CERT_FILE}
    SSLCertificateKeyFile ${KEY_FILE}
    SSLProtocol           all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite        HIGH:!aNULL:!MD5

    <Directory "/var/www/html">
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    ErrorLog  /var/log/httpd/ssl_error.log
    CustomLog /var/log/httpd/ssl_access.log combined
</VirtualHost>
EOF

        # Agregar Listen HTTPS si no existe
        grep -q "Listen $puerto_https" /etc/httpd/conf/httpd.conf || \
            echo "Listen $puerto_https" >> /etc/httpd/conf/httpd.conf

        # Habilitar mod_rewrite y mod_ssl
        sed -i 's/#LoadModule rewrite_module/LoadModule rewrite_module/' \
            /etc/httpd/conf.modules.d/*.conf 2>/dev/null || true

        echo -e "${GREEN}[+] SSL configurado en puerto $puerto_https con redirección desde $puerto_http.${NC}"
    fi

    configurar_firewall "$puerto_http"
    systemctl enable httpd &>/dev/null
    systemctl restart httpd && \
        echo -e "${GREEN}${BOLD}[+] Apache activo. HTTP: $puerto_http${[ "$ACTIVAR_SSL" = "yes" ] && echo " | HTTPS: $puerto_https"}${NC}" || \
        echo -e "${RED}[-] Error al reiniciar Apache.${NC}"

    echo -ne "\n${BLUE}Presiona Enter...${NC}"; read
}

# ============================================================
# NGINX - INSTALACIÓN + SSL
# ============================================================

function menu_nginx() {
    clear
    echo -e "${CYAN}--- Nginx - Práctica 7 ---${NC}"
    elegir_origen
    [ "$ORIGEN" = "FTP" ] && instalar_nginx_ftp || instalar_nginx_web
}

function instalar_nginx_web() {
    if rpm -q nginx &>/dev/null; then
        read -p $'\e[1;33m¿Reinstalar Nginx? [s/N]: \e[0m' r
        [[ "$r" =~ ^[sS]$ ]] && { systemctl stop nginx &>/dev/null; dnf remove -y -q nginx &>/dev/null; } || return
    fi
    echo -e "${BLUE}[*] Instalando Nginx...${NC}"
    dnf install -y -q nginx &>/dev/null || { echo -e "${RED}[-] Error.${NC}"; read; return 1; }
    _configurar_nginx_comun
}

function instalar_nginx_ftp() {
    navegar_ftp_y_seleccionar || { read; return 1; }
    local dest="/tmp/${ARCHIVO_SELECCIONADO}"
    descargar_y_validar_hash "$RUTA_FTP_ARCHIVO" "$dest" || { read; return 1; }

    echo -e "${BLUE}[*] Instalando $ARCHIVO_SELECCIONADO...${NC}"
    [[ "$ARCHIVO_SELECCIONADO" == *.rpm ]] && dnf install -y -q "$dest" &>/dev/null || \
        dnf install -y -q nginx &>/dev/null
    rm -f "$dest"
    _configurar_nginx_comun
}

function _configurar_nginx_comun() {
    preguntar_ssl
    pedir_puerto "HTTP"
    local puerto_http="$PUERTO_SELECCIONADO"

    local ver_real
    ver_real=$(nginx -v 2>&1 | grep -oP 'nginx/\K[\d.]+' || echo "desconocida")

    mkdir -p /usr/share/nginx/html
    crear_index "/usr/share/nginx/html" "Nginx" "$ver_real" "$puerto_http" "$ACTIVAR_SSL"
    chown -R nginx:nginx /usr/share/nginx/html

    if [ "$ACTIVAR_SSL" = "yes" ]; then
        verificar_o_generar_cert
        pedir_puerto "HTTPS"
        local puerto_https="$PUERTO_SELECCIONADO"
        configurar_firewall "$puerto_https"

        cat > /etc/nginx/conf.d/reprobados_ssl.conf << EOF
# HTTP → HTTPS redirect
server {
    listen ${puerto_http};
    server_name ${DOMAIN};
    return 301 https://\$host:${puerto_https}\$request_uri;
}

# HTTPS server
server {
    listen ${puerto_https} ssl;
    server_name ${DOMAIN};

    ssl_certificate     ${CERT_FILE};
    ssl_certificate_key ${KEY_FILE};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    root  /usr/share/nginx/html;
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }

    access_log /var/log/nginx/ssl_access.log;
    error_log  /var/log/nginx/ssl_error.log;
}
EOF
        echo -e "${GREEN}[+] Nginx SSL configurado en puerto $puerto_https.${NC}"
    else
        # Config HTTP simple
        cat > /etc/nginx/conf.d/reprobados.conf << EOF
server {
    listen ${puerto_http};
    server_name ${DOMAIN} _;
    root  /usr/share/nginx/html;
    index index.html;
    location / { try_files \$uri \$uri/ =404; }
}
EOF
    fi

    configurar_firewall "$puerto_http"
    systemctl enable nginx &>/dev/null
    nginx -t 2>/dev/null && systemctl restart nginx && \
        echo -e "${GREEN}${BOLD}[+] Nginx activo en puerto $puerto_http${NC}" || \
        { echo -e "${RED}[-] Error en configuración Nginx.${NC}"; nginx -t; }

    echo -ne "\n${BLUE}Presiona Enter...${NC}"; read
}

# ============================================================
# TOMCAT - INSTALACIÓN + SSL
# ============================================================

function menu_tomcat() {
    clear
    echo -e "${CYAN}--- Apache Tomcat - Práctica 7 ---${NC}"
    elegir_origen
    [ "$ORIGEN" = "FTP" ] && instalar_tomcat_ftp || instalar_tomcat_web
}

function _obtener_versiones_tomcat() {
    local base="https://downloads.apache.org/tomcat"
    TOMCAT_LATEST=$(curl -s "${base}/tomcat-11/" | grep -oP '(?<=v)[\d.]+(?=/)' | sort -V | tail -1)
    TOMCAT_LTS=$(curl -s "${base}/tomcat-10/" | grep -oP '(?<=v)[\d.]+(?=/)' | sort -V | tail -1)
    TOMCAT_V9=$(curl -s "${base}/tomcat-9/" | grep -oP '(?<=v)[\d.]+(?=/)' | sort -V | tail -1)
    [ -z "$TOMCAT_LATEST" ] && TOMCAT_LATEST="11.0.2"
    [ -z "$TOMCAT_LTS" ]    && TOMCAT_LTS="10.1.34"
    [ -z "$TOMCAT_V9" ]     && TOMCAT_V9="9.0.99"
}

function instalar_tomcat_web() {
    _obtener_versiones_tomcat
    echo -e "\n${CYAN}Versiones disponibles de Tomcat:${NC}"
    echo -e "  1) $TOMCAT_V9      ${BLUE}[Rama 9]${NC}"
    echo -e "  2) $TOMCAT_LTS     ${CYAN}[LTS/Estable]${NC}"
    echo -e "  3) $TOMCAT_LATEST  ${GREEN}[Latest]${NC}"

    local sel=""
    while true; do
        read -p $'\e[1;33mSelecciona versión [1-3]: \e[0m' sel
        [[ "$sel" =~ ^[1-3]$ ]] && break
        echo -e "${RED}[!] Inválido.${NC}"
    done
    local tc_ver
    case "$sel" in 1) tc_ver="$TOMCAT_V9";; 2) tc_ver="$TOMCAT_LTS";; 3) tc_ver="$TOMCAT_LATEST";; esac
    local tc_major; tc_major=$(echo "$tc_ver" | cut -d. -f1)

    local tc_url="https://downloads.apache.org/tomcat/tomcat-${tc_major}/v${tc_ver}/bin/apache-tomcat-${tc_ver}.tar.gz"
    local tc_tar="/tmp/tomcat.tar.gz"
    echo -e "${BLUE}[*] Descargando Tomcat $tc_ver...${NC}"
    curl -L -f -s --max-time 180 -o "$tc_tar" "$tc_url" || { echo -e "${RED}[-] Error de descarga.${NC}"; read; return 1; }
    tar -tzf "$tc_tar" &>/dev/null || { echo -e "${RED}[-] Archivo corrupto.${NC}"; rm -f "$tc_tar"; read; return 1; }

    _instalar_tomcat_comun "$tc_tar" "$tc_ver"
}

function instalar_tomcat_ftp() {
    navegar_ftp_y_seleccionar || { read; return 1; }
    local dest="/tmp/${ARCHIVO_SELECCIONADO}"
    descargar_y_validar_hash "$RUTA_FTP_ARCHIVO" "$dest" || { read; return 1; }

    # Deducir versión del nombre de archivo
    local tc_ver
    tc_ver=$(echo "$ARCHIVO_SELECCIONADO" | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1)
    [ -z "$tc_ver" ] && tc_ver="desconocida"

    _instalar_tomcat_comun "$dest" "$tc_ver"
    rm -f "$dest"
}

function _instalar_tomcat_comun() {
    local tc_tar=$1 tc_ver=$2
    local tc_dir="/opt/tomcat"

    preguntar_ssl
    pedir_puerto "HTTP (Tomcat)"
    local puerto_http="$PUERTO_SELECCIONADO"

    dnf install -y -q java-17-openjdk &>/dev/null

    mkdir -p "$tc_dir"
    tar -xzf "$tc_tar" -C "$tc_dir" --strip-components=1 2>/dev/null
    [ "$tc_tar" != "/tmp/tomcat.tar.gz" ] || rm -f "$tc_tar"

    id tomcat &>/dev/null || useradd -r -s /sbin/nologin -d "$tc_dir" tomcat &>/dev/null
    rm -rf "$tc_dir/webapps/"*
    sed -i "s/port=\"8080\"/port=\"$puerto_http\"/" "$tc_dir/conf/server.xml"

    local java_bin; java_bin=$(readlink -f "$(which java)")
    local java_home; java_home=$(dirname "$(dirname "$java_bin")")
    [ -d "$java_home" ] || java_home=$(find /usr/lib/jvm -maxdepth 1 -name "java-17*" -type d | head -1)
    local libjli; libjli=$(find "$java_home" -name "libjli.so" 2>/dev/null | head -1)
    local jli_dir; jli_dir=$(dirname "$libjli")

    cat > "$tc_dir/bin/setenv.sh" << SETEOF
#!/bin/bash
export JAVA_HOME=${java_home}
export CATALINA_HOME=${tc_dir}
export CATALINA_PID=${tc_dir}/tomcat.pid
export CATALINA_OPTS="-Xms256m -Xmx512m"
export LD_LIBRARY_PATH=${jli_dir}:\$LD_LIBRARY_PATH
SETEOF
    chmod +x "$tc_dir/bin/setenv.sh"

    mkdir -p "$tc_dir/webapps/ROOT"
    crear_index "$tc_dir/webapps/ROOT" "Apache Tomcat" "$tc_ver" "$puerto_http" "$ACTIVAR_SSL"

    if [ "$ACTIVAR_SSL" = "yes" ]; then
        verificar_o_generar_cert
        pedir_puerto "HTTPS (Tomcat)"
        local puerto_https="$PUERTO_SELECCIONADO"
        configurar_firewall "$puerto_https"

        # Convertir PEM a PKCS12 para Java
        local p12_file="$SSL_DIR/reprobados.p12"
        openssl pkcs12 -export -in "$CERT_FILE" -inkey "$KEY_FILE" \
            -out "$p12_file" -name reprobados -passout pass:changeit 2>/dev/null
        chown tomcat:tomcat "$p12_file"
        chmod 640 "$p12_file"

        # Agregar conector HTTPS en server.xml (antes de </Service>)
        python3 - "$tc_dir/conf/server.xml" "$puerto_http" "$puerto_https" "$p12_file" << 'PYEOF'
import sys, re
path, ph, phs, p12 = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(path) as f: content = f.read()

# Redirección HTTP → HTTPS
redirect = f'redirectPort="{phs}"'
content = re.sub(r'redirectPort="\d+"', redirect, content)

# Conector HTTPS
https_connector = f"""
    <!-- Conector HTTPS - Practica 7 -->
    <Connector port="{phs}" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true">
        <SSLHostConfig>
            <Certificate certificateKeystoreFile="{p12}" type="RSA"
                         certificateKeystorePassword="changeit"
                         certificateKeystoreType="PKCS12"/>
        </SSLHostConfig>
    </Connector>
"""
content = content.replace('</Service>', https_connector + '</Service>')

with open(path, 'w') as f: f.write(content)
print(f"[+] Conector HTTPS en puerto {phs} agregado a server.xml")
PYEOF
        echo -e "${GREEN}[+] Tomcat SSL configurado en puerto $puerto_https.${NC}"
    fi

    chown -R tomcat:tomcat "$tc_dir"
    chmod 755 "$tc_dir"; chmod 750 "$tc_dir/conf"
    chmod +x "$tc_dir/bin/"*.sh
    configurar_firewall "$puerto_http"

    # Authbind para puertos < 1024
    local usar_authbind="no"
    for p in "$puerto_http" "${puerto_https:-0}"; do
        [ "$p" -lt 1024 ] 2>/dev/null || continue
        dnf install -y -q authbind &>/dev/null
        command -v authbind &>/dev/null && {
            touch "/etc/authbind/byport/$p"
            chown tomcat:tomcat "/etc/authbind/byport/$p"
            chmod 500 "/etc/authbind/byport/$p"
            usar_authbind="yes"
        }
    done

    local exec_start="$tc_dir/bin/startup.sh"
    [ "$usar_authbind" = "yes" ] && exec_start="/usr/bin/authbind --deep $tc_dir/bin/startup.sh"

    cat > /etc/systemd/system/tomcat.service << SYSDEOF
[Unit]
Description=Apache Tomcat ${tc_ver}
After=network.target

[Service]
Type=forking
User=tomcat
Group=tomcat
Environment="JAVA_HOME=${java_home}"
Environment="CATALINA_HOME=${tc_dir}"
Environment="CATALINA_PID=${tc_dir}/tomcat.pid"
ExecStart=${exec_start}
ExecStop=${tc_dir}/bin/shutdown.sh
SuccessExitStatus=143
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
SYSDEOF

    systemctl daemon-reload &>/dev/null
    systemctl enable tomcat &>/dev/null
    echo -e "${BLUE}[*] Iniciando Tomcat...${NC}"
    systemctl start tomcat

    # Esperar 20 segundos
    for i in {1..20}; do
        sleep 1
        ss -tlnp 2>/dev/null | grep -q ":${puerto_http} " && break
    done

    if systemctl is-active --quiet tomcat; then
        echo -e "${GREEN}${BOLD}[+] Tomcat activo en puerto $puerto_http.${NC}"
    else
        echo -e "${RED}[-] Tomcat no inició. Log:${NC}"
        journalctl -u tomcat -n 15 --no-pager
        tail -15 "$tc_dir/logs/catalina.out" 2>/dev/null
    fi
    echo -ne "\n${BLUE}Presiona Enter...${NC}"; read
}

# ============================================================
# vsftpd - INSTALACIÓN + FTPS (SSL)
# ============================================================

function menu_vsftpd() {
    clear
    echo -e "${CYAN}--- vsftpd (FTP/FTPS) - Práctica 7 ---${NC}"
    elegir_origen
    [ "$ORIGEN" = "FTP" ] && instalar_vsftpd_ftp || instalar_vsftpd_web
}

function instalar_vsftpd_web() {
    if rpm -q vsftpd &>/dev/null; then
        read -p $'\e[1;33m¿Reinstalar vsftpd? [s/N]: \e[0m' r
        [[ "$r" =~ ^[sS]$ ]] && { systemctl stop vsftpd &>/dev/null; dnf remove -y -q vsftpd &>/dev/null; } || return
    fi
    echo -e "${BLUE}[*] Instalando vsftpd...${NC}"
    dnf install -y -q vsftpd &>/dev/null || { echo -e "${RED}[-] Error.${NC}"; read; return 1; }
    _configurar_vsftpd_comun
}

function instalar_vsftpd_ftp() {
    navegar_ftp_y_seleccionar || { read; return 1; }
    local dest="/tmp/${ARCHIVO_SELECCIONADO}"
    descargar_y_validar_hash "$RUTA_FTP_ARCHIVO" "$dest" || { read; return 1; }

    echo -e "${BLUE}[*] Instalando vsftpd desde FTP...${NC}"
    [[ "$ARCHIVO_SELECCIONADO" == *.rpm ]] && dnf install -y -q "$dest" &>/dev/null || \
        dnf install -y -q vsftpd &>/dev/null
    rm -f "$dest"
    _configurar_vsftpd_comun
}

function _configurar_vsftpd_comun() {
    preguntar_ssl

    # Crear usuario FTP si no existe
    local ftp_user="ftpuser"
    local ftp_home="/srv/ftp/repo"
    if ! id "$ftp_user" &>/dev/null; then
        useradd -m -d "$ftp_home" -s /sbin/nologin "$ftp_user" &>/dev/null
        echo "ftpuser:FTP@Practica7!" | chpasswd
        echo -e "${GREEN}[+] Usuario FTP '${ftp_user}' creado (pass: FTP\@Practica7!).${NC}"
    fi

    mkdir -p "$ftp_home"
    chmod 755 "$ftp_home"
    chown "$ftp_user":"$ftp_user" "$ftp_home"

    # Estructura del repositorio
    for os in Linux Windows; do
        for srv in Apache Nginx Tomcat; do
            mkdir -p "$ftp_home/http/$os/$srv"
        done
    done
    chown -R "$ftp_user":"$ftp_user" "$ftp_home"

    # Certificado FTPS
    local ftps_cert="/etc/vsftpd/vsftpd.pem"
    local ftps_key="/etc/vsftpd/vsftpd.key"

    if [ "$ACTIVAR_SSL" = "yes" ]; then
        echo -e "${BLUE}[*] Generando certificado para FTPS...${NC}"
        mkdir -p /etc/vsftpd
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$ftps_key" \
            -out    "$ftps_cert" \
            -subj   "/C=MX/ST=Sinaloa/L=Culiacan/O=Reprobados/OU=FTP/CN=${DOMAIN}" \
            2>/dev/null
        chmod 600 "$ftps_key" "$ftps_cert"
        echo -e "${GREEN}[+] Certificado FTPS generado.${NC}"
    fi

    # Habilitar puerto pasivo en firewall
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-service=ftp &>/dev/null
        firewall-cmd --permanent --add-port=40000-40100/tcp &>/dev/null
        firewall-cmd --reload &>/dev/null
    fi
    # SELinux
    if command -v setsebool &>/dev/null; then
        setsebool -P allow_ftpd_full_access 1 &>/dev/null
        setsebool -P ftpd_use_passive_mode 1 &>/dev/null
    fi

    # Backup de configuración original
    cp /etc/vsftpd/vsftpd.conf /etc/vsftpd/vsftpd.conf.bak 2>/dev/null

    local local_ip
    local_ip=$(hostname -I | awk '{print $1}')

    if [ "$ACTIVAR_SSL" = "yes" ]; then
        cat > /etc/vsftpd/vsftpd.conf << EOF
# ── vsftpd - Práctica 7 (FTPS) ──
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
xferlog_enable=YES
connect_from_port_20=YES
xferlog_std_format=YES
chroot_local_user=YES
allow_writeable_chroot=YES
local_root=${ftp_home}
userlist_enable=YES
userlist_deny=NO
userlist_file=/etc/vsftpd/user_list

# ── Modo Pasivo ──
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
pasv_address=${local_ip}

# ── FTPS (SSL Explícito) ──
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=NO
ssl_sslv2=NO
ssl_sslv3=NO
ssl_tlsv1_1=NO
ssl_tlsv1_2=YES
ssl_tlsv1_3=YES
require_ssl_reuse=NO
ssl_ciphers=HIGH
rsa_cert_file=${ftps_cert}
rsa_private_key_file=${ftps_key}

# ── Logs ──
xferlog_file=/var/log/vsftpd.log
EOF
    else
        cat > /etc/vsftpd/vsftpd.conf << EOF
# ── vsftpd - Práctica 7 (FTP sin SSL) ──
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=YES
allow_writeable_chroot=YES
local_root=${ftp_home}
userlist_enable=YES
userlist_deny=NO
userlist_file=/etc/vsftpd/user_list
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
pasv_address=${local_ip}
xferlog_file=/var/log/vsftpd.log
EOF
    fi

    # Lista blanca de usuarios
    echo "$ftp_user" > /etc/vsftpd/user_list

    systemctl enable vsftpd &>/dev/null
    systemctl restart vsftpd && \
        echo -e "${GREEN}${BOLD}[+] vsftpd activo${ACTIVAR_SSL:+ (FTPS habilitado)}.${NC}" || \
        { echo -e "${RED}[-] Error al iniciar vsftpd.${NC}"; journalctl -u vsftpd -n 10 --no-pager; }

    echo -e "\n${CYAN}Información del repositorio FTP:${NC}"
    echo -e "  Host:     ${local_ip}"
    echo -e "  Usuario:  ${ftp_user}"
    echo -e "  Password: FTP@Practica7!"
    echo -e "  Raíz:     ${ftp_home}"
    echo -e "  FTPS:     ${ACTIVAR_SSL}"
    echo -ne "\n${BLUE}Presiona Enter...${NC}"; read
}

# ============================================================
# VERIFICACIÓN GLOBAL DE SERVICIOS
# ============================================================

function verificar_todos_servicios() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     RESUMEN DE VERIFICACIÓN DE SERVICIOS             ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""

    local ok="${GREEN}✓ ACTIVO${NC}"
    local ko="${RED}✗ INACTIVO${NC}"

    # Apache
    echo -e "${YELLOW}── Apache (httpd) ──${NC}"
    if systemctl is-active --quiet httpd 2>/dev/null; then
        echo -e "  Estado: $ok"
        local apache_http; apache_http=$(ss -tlnp | grep httpd | awk '{print $4}' | grep -oP ':\K\d+' | head -1)
        echo -e "  Puerto HTTP:  ${apache_http:-no detectado}"
        # Verificar SSL
        if grep -q "SSLEngine on" /etc/httpd/conf.d/ssl_reprobados.conf 2>/dev/null; then
            local apache_https; apache_https=$(grep "VirtualHost \*:" /etc/httpd/conf.d/ssl_reprobados.conf | tail -1 | grep -oP '\d+')
            echo -e "  Puerto HTTPS: ${apache_https:-no detectado}"
            _verificar_ssl_https "$apache_https" "Apache"
        else
            echo -e "  SSL: ${YELLOW}No configurado${NC}"
        fi
    else
        echo -e "  Estado: $ko"
    fi
    echo ""

    # Nginx
    echo -e "${YELLOW}── Nginx ──${NC}"
    if systemctl is-active --quiet nginx 2>/dev/null; then
        echo -e "  Estado: $ok"
        local nginx_https; nginx_https=$(grep "listen.*ssl" /etc/nginx/conf.d/reprobados_ssl.conf 2>/dev/null | grep -oP '\d+' | head -1)
        if [ -n "$nginx_https" ]; then
            echo -e "  Puerto HTTPS: $nginx_https"
            _verificar_ssl_https "$nginx_https" "Nginx"
        else
            echo -e "  SSL: ${YELLOW}No configurado${NC}"
        fi
    else
        echo -e "  Estado: $ko"
    fi
    echo ""

    # Tomcat
    echo -e "${YELLOW}── Apache Tomcat ──${NC}"
    if systemctl is-active --quiet tomcat 2>/dev/null; then
        echo -e "  Estado: $ok"
        local tc_https; tc_https=$(grep -oP '(?<=port=")\d+(?=".*SSLEnabled)' /opt/tomcat/conf/server.xml 2>/dev/null | head -1)
        if [ -n "$tc_https" ]; then
            echo -e "  Puerto HTTPS: $tc_https"
            _verificar_ssl_https "$tc_https" "Tomcat"
        else
            echo -e "  SSL: ${YELLOW}No configurado${NC}"
        fi
    else
        echo -e "  Estado: $ko"
    fi
    echo ""

    # vsftpd
    echo -e "${YELLOW}── vsftpd (FTP/FTPS) ──${NC}"
    if systemctl is-active --quiet vsftpd 2>/dev/null; then
        echo -e "  Estado: $ok"
        local ssl_activo; ssl_activo=$(grep -c "ssl_enable=YES" /etc/vsftpd/vsftpd.conf 2>/dev/null)
        [ "$ssl_activo" -gt 0 ] && \
            echo -e "  FTPS: ${GREEN}Habilitado${NC}" || \
            echo -e "  FTPS: ${YELLOW}No configurado${NC}"
        echo -e "  Puerto: 21 (control)"
    else
        echo -e "  Estado: $ko"
    fi
    echo ""

    # Certificado
    echo -e "${YELLOW}── Certificado SSL ──${NC}"
    if [ -f "$CERT_FILE" ]; then
        local exp; exp=$(openssl x509 -noout -enddate -in "$CERT_FILE" 2>/dev/null | cut -d= -f2)
        local cn;  cn=$(openssl x509 -noout -subject -in "$CERT_FILE" 2>/dev/null | grep -oP 'CN\s*=\s*\K[^,/]+')
        echo -e "  Archivo: $CERT_FILE"
        echo -e "  CN:      $cn"
        echo -e "  Expira:  $exp"
    else
        echo -e "  ${YELLOW}No generado aún.${NC}"
    fi

    echo ""
    echo -ne "${BLUE}Presiona Enter para continuar...${NC}"; read
}

function _verificar_ssl_https() {
    local puerto=$1 servicio=$2
    if [ -z "$puerto" ]; then return; fi
    local ip; ip=$(hostname -I | awk '{print $1}')
    local resultado
    resultado=$(echo | openssl s_client -connect "${ip}:${puerto}" \
        -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}✓ SSL verificado: $resultado${NC}"
    else
        echo -e "  ${RED}✗ No se pudo verificar SSL en ${ip}:${puerto}${NC}"
    fi
}