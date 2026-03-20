#!/bin/bash
# ============================================================
# p7_functions.sh - Funciones de Aprovisionamiento (Linux)
# Práctica 7: SSL/TLS + Cliente FTP dinámico + Hash
# Basado en http_functions.sh (Práctica 6)
# ============================================================

# ── COLORES ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

# ── CONSTANTES P7 ─────────────────────────────────────────────
DOMAIN="www.reprobados.com"
SSL_DIR="/etc/ssl/reprobados"
CERT_FILE="$SSL_DIR/reprobados.crt"
KEY_FILE="$SSL_DIR/reprobados.key"

# Puertos que no se permiten para servidores HTTP
PUERTOS_RESERVADOS=(20 21 22 23 25 53 67 68 69 110 111 123 135 137 138 139 143
                    161 162 389 445 465 500 514 587 636 993 995 1433 1521
                    2049 3306 3389 5432 5900 8443)

# ============================================================
# UTILIDADES  (igual que práctica 6, sin cambios)
# ============================================================

function verificar_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}${BOLD}[-] Error: Debes ejecutar este script como root.${NC}"
        exit 1
    fi
    echo -e "${BLUE}[*] Verificando dependencias del sistema...${NC}"
    dnf install -y -q policycoreutils-python-utils bind-utils openssl curl wget mod_ssl &>/dev/null
}

function puerto_es_reservado() {
    local puerto=$1
    for p in "${PUERTOS_RESERVADOS[@]}"; do
        [ "$puerto" -eq "$p" ] && return 0
    done
    return 1
}

function puerto_en_uso() {
    ss -tlnp 2>/dev/null | grep -q ":$1 "
}

function pedir_puerto() {
    local etiqueta="${1:-escucha}"
    local puerto=""
    while true; do
        echo -ne "${YELLOW}Ingresa el puerto de $etiqueta (ej. 80, 443, 8080): ${NC}"
        read puerto
        if [[ ! "$puerto" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}[!] El puerto debe ser numérico.${NC}"; continue
        fi
        if [ "$puerto" -lt 1 ] || [ "$puerto" -gt 65535 ]; then
            echo -e "${RED}[!] Puerto fuera de rango (1-65535).${NC}"; continue
        fi
        if puerto_es_reservado "$puerto"; then
            echo -e "${RED}[!] El puerto $puerto está reservado para otro servicio crítico.${NC}"; continue
        fi
        if puerto_en_uso "$puerto"; then
            echo -e "${RED}[!] El puerto $puerto ya está en uso por otro proceso.${NC}"; continue
        fi
        break
    done
    PUERTO_SELECCIONADO="$puerto"
}

function configurar_firewall() {
    local puerto=$1
    local servicio="${2:-http}"   # segundo argumento opcional: http | nginx | ftp

    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port="${puerto}/tcp" &>/dev/null
        firewall-cmd --reload &>/dev/null
        echo -e "${BLUE}[*] Firewall: puerto $puerto habilitado.${NC}"
    fi

    if command -v semanage &>/dev/null; then
        semanage port -a -t http_port_t -p tcp "$puerto" 2>/dev/null || \
        semanage port -m -t http_port_t -p tcp "$puerto" 2>/dev/null
        echo -e "${BLUE}[*] SELinux: puerto $puerto autorizado para HTTP.${NC}"
    fi

    # Para Nginx con puertos < 1024: otorgar capability net_bind_service
    if [ "$servicio" = "nginx" ] && [ "$puerto" -lt 1024 ]; then
        local nginx_bin
        nginx_bin=$(which nginx 2>/dev/null)
        if [ -n "$nginx_bin" ]; then
            setcap 'cap_net_bind_service=+ep' "$nginx_bin" 2>/dev/null && \
                echo -e "${BLUE}[*] setcap net_bind_service otorgado a nginx para puerto $puerto.${NC}"
            # Arreglar permisos del pid file para que nginx no root pueda escribirlo
            touch /run/nginx.pid 2>/dev/null
            chown nginx:nginx /run/nginx.pid 2>/dev/null
            # Contexto SELinux para el pid
            restorecon /run/nginx.pid 2>/dev/null || true
        fi
    fi
}

# crear_index: misma firma que práctica 6 + parámetro opcional ssl
function crear_index() {
    local directorio=$1 servicio=$2 version=$3 puerto=$4 ssl=${5:-no}
    mkdir -p "$directorio"
    local proto="HTTP"
    [ "$ssl" = "yes" ] && proto="HTTPS (SSL/TLS)"
    cat > "$directorio/index.html" << HTML
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>${servicio} - Servidor Web</title>
  <style>
    body { font-family: Arial, sans-serif; background: #0d1117; color: #c9d1d9;
           display: flex; justify-content: center; align-items: center;
           height: 100vh; margin: 0; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 10px;
            padding: 40px 60px; text-align: center; }
    h1 { color: #58a6ff; }
    span { color: #3fb950; font-weight: bold; }
    .ssl { color: #f0883e; font-weight: bold; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Servidor Web Activo</h1>
    <p>Servidor: <span>${servicio}</span></p>
    <p>Versión:  <span>${version}</span></p>
    <p>Puerto:   <span>${puerto}</span></p>
    <p>Protocolo: <span class="ssl">${proto}</span></p>
    <p>Dominio:  <span>${DOMAIN}</span></p>
    <hr style="border-color:#30363d; margin:20px 0;">
    <small>Infraestructura SSL/TLS - Práctica 7</small>
  </div>
</body>
</html>
HTML
    chmod 644 "$directorio/index.html"
    echo -e "${BLUE}[*] Página index.html generada en $directorio.${NC}"
}

# ============================================================
# NUEVAS FUNCIONES P7 - ORIGEN, SSL, FTP
# ============================================================

# ── Pregunta origen: WEB o FTP ────────────────────────────────
function elegir_origen() {
    echo ""
    echo -e "${CYAN}--- Fuente de instalación ---${NC}"
    echo -e "  1. WEB  (gestor de paquetes / repositorio oficial)"
    echo -e "  2. FTP  (repositorio privado)"
    echo ""
    local sel=""
    while true; do
        read -p $'\e[1;33mElige origen [1-2]: \e[0m' sel
        case "$sel" in
            1) ORIGEN="WEB"; break ;;
            2) ORIGEN="FTP"; _pedir_datos_ftp; break ;;
            *) echo -e "${RED}[!] Opción inválida.${NC}" ;;
        esac
    done
}

function _pedir_datos_ftp() {
    echo ""
    read -p $'\e[1;33mIP del servidor FTP: \e[0m'      FTP_HOST
    read -p $'\e[1;33mUsuario FTP: \e[0m'               FTP_USER
    read -s -p $'\e[1;33mContraseña FTP: \e[0m'         FTP_PASS
    echo ""
}

# ── Pregunta activar SSL ──────────────────────────────────────
function preguntar_ssl() {
    echo ""
    read -p $'\e[1;33m¿Desea activar SSL/TLS en este servicio? [S/N]: \e[0m' _resp_ssl
    [[ "$_resp_ssl" =~ ^[sS]$ ]] && ACTIVAR_SSL="yes" || ACTIVAR_SSL="no"
}

# ── Certificado autofirmado ───────────────────────────────────
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
    echo -e "${GREEN}[+] Certificado: $CERT_FILE${NC}"
    echo -e "${GREEN}[+] Llave:        $KEY_FILE${NC}"
}

function verificar_o_generar_cert() {
    if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
        local exp
        exp=$(openssl x509 -noout -enddate -in "$CERT_FILE" 2>/dev/null | cut -d= -f2)
        echo -e "${YELLOW}[!] Ya existe un certificado (expira: $exp).${NC}"
        read -p $'\e[1;33m¿Regenerar certificado? (s/n): \e[0m' regen
        [[ "$regen" =~ ^[sS]$ ]] && generar_certificado_ssl
    else
        generar_certificado_ssl
    fi
}

# ── Cliente FTP dinámico ──────────────────────────────────────

function ftp_listar_directorios() {
    local ruta=$1
    curl -s --list-only \
         -u "${FTP_USER}:${FTP_PASS}" \
         "ftp://${FTP_HOST}${ruta}" 2>/dev/null \
    | grep -v '^\.' | grep -v '\.' | sort
}

function ftp_listar_archivos() {
    local ruta=$1
    curl -s --list-only \
         -u "${FTP_USER}:${FTP_PASS}" \
         "ftp://${FTP_HOST}${ruta}" 2>/dev/null \
    | grep '\.' | sort
}

function ftp_descargar() {
    local ruta_remota=$1 destino=$2
    echo -e "${BLUE}[*] Descargando ftp://${FTP_HOST}${ruta_remota}...${NC}"
    curl -# -u "${FTP_USER}:${FTP_PASS}" \
         "ftp://${FTP_HOST}${ruta_remota}" \
         -o "$destino"
    return $?
}

# Navega el FTP y pone resultado en ARCHIVO_SELECCIONADO / RUTA_FTP_ARCHIVO
function navegar_ftp_y_seleccionar() {
    local os_dir="/http/Linux"
    echo -e "${CYAN}--- Navegando repositorio FTP: ${FTP_HOST}${os_dir} ---${NC}"

    # 1. Listar carpetas de servicio
    mapfile -t SERVICIOS < <(ftp_listar_directorios "${os_dir}/")
    if [ ${#SERVICIOS[@]} -eq 0 ]; then
        echo -e "${RED}[-] No se encontraron servicios en ${os_dir}/. Verifica conexión FTP.${NC}"
        return 1
    fi

    echo ""
    echo -e "${CYAN}--- Servicios disponibles en el repositorio ---${NC}"
    for i in "${!SERVICIOS[@]}"; do
        echo -e "  $((i+1)). ${SERVICIOS[$i]}"
    done
    echo ""

    local sel_srv=""
    while true; do
        echo -ne "${YELLOW}Selecciona servicio [1-${#SERVICIOS[@]}]: ${NC}"
        read sel_srv
        if [[ "$sel_srv" =~ ^[0-9]+$ ]] && \
           [ "$sel_srv" -ge 1 ] && [ "$sel_srv" -le "${#SERVICIOS[@]}" ]; then break; fi
        echo -e "${RED}[!] Selección inválida.${NC}"
    done

    local servicio="${SERVICIOS[$((sel_srv-1))]}"
    local ruta_srv="${os_dir}/${servicio}"

    # 2. Listar archivos instaladores (excluir .sha256 y .md5)
    mapfile -t TODOS_ARCH < <(ftp_listar_archivos "${ruta_srv}/")
    mapfile -t INSTALADORES < <(printf '%s\n' "${TODOS_ARCH[@]}" \
        | grep -v '\.sha256$' | grep -v '\.md5$')

    if [ ${#INSTALADORES[@]} -eq 0 ]; then
        echo -e "${RED}[-] No se encontraron instaladores en ${ruta_srv}/.${NC}"
        return 1
    fi

    echo ""
    echo -e "${CYAN}--- Instaladores disponibles para ${servicio} ---${NC}"
    for i in "${!INSTALADORES[@]}"; do
        echo -e "  $((i+1)). ${INSTALADORES[$i]}"
    done
    echo ""

    local sel_pkg=""
    while true; do
        echo -ne "${YELLOW}Selecciona versión [1-${#INSTALADORES[@]}]: ${NC}"
        read sel_pkg
        if [[ "$sel_pkg" =~ ^[0-9]+$ ]] && \
           [ "$sel_pkg" -ge 1 ] && [ "$sel_pkg" -le "${#INSTALADORES[@]}" ]; then break; fi
        echo -e "${RED}[!] Selección inválida.${NC}"
    done

    ARCHIVO_SELECCIONADO="${INSTALADORES[$((sel_pkg-1))]}"
    RUTA_FTP_ARCHIVO="${ruta_srv}/${ARCHIVO_SELECCIONADO}"
    echo -e "${GREEN}[+] Archivo seleccionado: $ARCHIVO_SELECCIONADO${NC}"
}

# Descarga el instalador y valida su hash SHA256/MD5
function descargar_y_validar_hash() {
    local ruta_remota=$1
    local destino=$2
    local nombre_archivo
    nombre_archivo=$(basename "$ruta_remota")
    local ruta_dir
    ruta_dir=$(dirname "$ruta_remota")

    # Descargar instalador
    if ! ftp_descargar "$ruta_remota" "$destino"; then
        echo -e "${RED}[-] Error al descargar $nombre_archivo.${NC}"
        return 1
    fi

    # Detectar tipo de hash disponible
    local hash_file="" hash_tipo=""
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
    echo -e "${BLUE}[*] Descargando hash ${hash_tipo^^}...${NC}"
    ftp_descargar "$hash_file" "$hash_tmp" &>/dev/null

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
        echo -e "${GREEN}${BOLD}[+] ✓ Integridad verificada: archivo íntegro.${NC}"
        return 0
    else
        echo -e "${RED}${BOLD}[-] ✗ INTEGRIDAD FALLIDA: archivo corrompido o alterado.${NC}"
        rm -f "$destino"
        return 1
    fi
}

# ============================================================
# APACHE
# ============================================================

function instalar_apache() {
    clear
    echo -e "${CYAN}--- Instalación de Apache (httpd) - Práctica 7 ---${NC}"

    elegir_origen

    # ── Instalación según origen ─────────────────────────────
    if [ "$ORIGEN" = "FTP" ]; then
        navegar_ftp_y_seleccionar || { echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1; }
        local dest_pkg="/tmp/${ARCHIVO_SELECCIONADO}"
        descargar_y_validar_hash "$RUTA_FTP_ARCHIVO" "$dest_pkg" || { echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1; }
        echo -e "${BLUE}[*] Instalando $ARCHIVO_SELECCIONADO...${NC}"
        dnf install -y -q "$dest_pkg" &>/dev/null || dnf install -y -q httpd &>/dev/null
        rm -f "$dest_pkg"
        dnf install -y -q mod_ssl &>/dev/null
    else
        # Mismo flujo de práctica 6: mostrar versiones y elegir
        if rpm -q httpd &>/dev/null; then
            echo -e "${YELLOW}[!] Apache ya está instalado en el sistema.${NC}"
            echo -ne "${YELLOW}¿Deseas reinstalarlo? (s/n): ${NC}"
            read resp
            if [[ ! "$resp" =~ ^[sS]$ ]]; then
                echo -e "${BLUE}[*] Omitiendo instalación.${NC}"
                echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return
            fi
            systemctl stop httpd &>/dev/null
            dnf remove -y -q httpd httpd-filesystem &>/dev/null
        fi

        echo -e "${BLUE}[*] Consultando versiones disponibles de 'httpd'...${NC}"
        mapfile -t VERSIONES < <(
            dnf list --showduplicates httpd 2>/dev/null \
                | awk 'NF>=3 && $1~/^httpd\./ { print $2 }' \
                | grep -v '^Name' | sort -uV | tail -3
        )
        [ ${#VERSIONES[@]} -eq 0 ] && VERSIONES=("disponible-en-repositorio")

        echo ""
        echo -e "${CYAN}--- Versiones disponibles para httpd ---${NC}"
        local total=${#VERSIONES[@]}
        for i in "${!VERSIONES[@]}"; do
            local num=$((i+1)) v="${VERSIONES[$i]}"
            if   [ "$num" -eq "$total" ];      then echo -e "  $num) $v  ${GREEN}[Latest]${NC}"
            elif [ "$num" -eq $((total-1)) ];  then echo -e "  $num) $v  ${CYAN}[LTS / Estable]${NC}"
            else                                    echo -e "  $num) $v"
            fi
        done
        echo ""

        local sel=""
        while true; do
            echo -ne "${YELLOW}Selecciona una versión [1-${total}]: ${NC}"
            read sel
            if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "$total" ]; then break; fi
            echo -e "${RED}[!] Selección inválida.${NC}"
        done
        local ver_elegida="${VERSIONES[$((sel-1))]}"
        echo -e "${GREEN}[+] Versión seleccionada: $ver_elegida${NC}"

        echo -e "${BLUE}[*] Instalando Apache ($ver_elegida) silenciosamente...${NC}"
        if ! dnf install -y -q "httpd-${ver_elegida}" &>/dev/null; then
            echo -e "${YELLOW}[!] Falló versión específica. Instalando versión por defecto...${NC}"
            if ! dnf install -y -q httpd &>/dev/null; then
                echo -e "${RED}[-] Error crítico instalando Apache.${NC}"
                dnf install -y "httpd-${ver_elegida}"
                echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1
            fi
        fi
        dnf install -y -q mod_ssl &>/dev/null
    fi

    # ── Configuración común (puerto, SSL, virtualhost) ───────
    local ver_real
    ver_real=$(httpd -v 2>/dev/null | grep -oP 'Apache/\K[\d.]+' || echo "desconocida")

    preguntar_ssl
    pedir_puerto "HTTP"
    local puerto_http="$PUERTO_SELECCIONADO"

    # Ajustar Listen en httpd.conf
    if grep -q "^Listen " /etc/httpd/conf/httpd.conf; then
        sed -i "s/^Listen .*/Listen $puerto_http/" /etc/httpd/conf/httpd.conf
    else
        echo "Listen $puerto_http" >> /etc/httpd/conf/httpd.conf
    fi
    echo -e "${BLUE}[*] Puerto $puerto_http configurado en httpd.conf.${NC}"

    # Cabeceras de seguridad (idénticas a práctica 6 + HSTS)
    cat > /etc/httpd/conf.d/security.conf << 'SECEOF'
ServerTokens Prod
ServerSignature Off
TraceEnable Off

<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</IfModule>

<Directory "/var/www/html">
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
</Directory>
SECEOF

    mkdir -p /var/www/html
    crear_index "/var/www/html" "Apache httpd" "$ver_real" "$puerto_http" "$ACTIVAR_SSL"
    chown -R apache:apache /var/www/html
    chmod -R 755 /var/www/html

    if [ "$ACTIVAR_SSL" = "yes" ]; then
        verificar_o_generar_cert

        pedir_puerto "HTTPS"
        local puerto_https="$PUERTO_SELECCIONADO"
        configurar_firewall "$puerto_https"

        # Asegurar que el puerto HTTPS también esté en httpd.conf
        grep -q "^Listen $puerto_https" /etc/httpd/conf/httpd.conf || \
            echo "Listen $puerto_https" >> /etc/httpd/conf/httpd.conf

        # Habilitar mod_rewrite si no está activo
        if ! grep -q "^LoadModule rewrite_module" /etc/httpd/conf.modules.d/00-base.conf 2>/dev/null; then
            sed -i 's/#LoadModule rewrite_module/LoadModule rewrite_module/' \
                /etc/httpd/conf.modules.d/00-base.conf 2>/dev/null || true
        fi

        # Deshabilitar ssl.conf por defecto de mod_ssl (tiene Listen 443 hardcodeado)
        [ -f /etc/httpd/conf.d/ssl.conf ] && \
            mv /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/ssl.conf.disabled

        # Obtener IP local para el redirect (Redirect no acepta variables Apache)
        local server_ip
        server_ip=$(hostname -I | awk '{print $1}')

        # ── VirtualHost HTTP → HTTPS ──
        cat > /etc/httpd/conf.d/redirect_http.conf << EOF
# Redireccion HTTP → HTTPS para Apache - Practica 7
<VirtualHost *:${puerto_http}>
    ServerName ${DOMAIN}
    ServerAlias *
    Redirect permanent / https://${server_ip}:${puerto_https}/
</VirtualHost>
EOF

        # ── VirtualHost HTTPS ──
        cat > /etc/httpd/conf.d/ssl_reprobados.conf << EOF
# VirtualHost HTTPS - Practica 7
<VirtualHost *:${puerto_https}>
    ServerName ${DOMAIN}
    ServerAlias *
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile    ${CERT_FILE}
    SSLCertificateKeyFile ${KEY_FILE}
    SSLProtocol           all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite        HIGH:!aNULL:!MD5
    SSLHonorCipherOrder   on

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
        echo -e "${GREEN}[+] SSL configurado: HTTP $puerto_http → HTTPS $puerto_https (IP: ${server_ip}).${NC}"
    fi

    configurar_firewall "$puerto_http"
    systemctl enable httpd &>/dev/null

    # Validar config antes de reiniciar
    if ! httpd -t 2>/dev/null; then
        echo -e "${RED}[-] Error en la configuración de Apache:${NC}"
        httpd -t
        echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1
    fi

    if ! systemctl restart httpd; then
        echo -e "${RED}[-] Error al reiniciar Apache:${NC}"
        journalctl -u httpd -n 20 --no-pager
        echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1
    fi

    echo -e "${GREEN}${BOLD}[+] Apache configurado correctamente en el puerto $puerto_http.${NC}"
    [ "$ACTIVAR_SSL" = "yes" ] && \
        echo -e "${GREEN}${BOLD}[+] HTTPS activo en puerto $puerto_https.${NC}"
    echo -ne "\n${BLUE}Presiona Enter...${NC}"; read
}

# ============================================================
# NGINX
# ============================================================

function instalar_nginx() {
    clear
    echo -e "${CYAN}--- Instalación de Nginx - Práctica 7 ---${NC}"

    elegir_origen

    # ── Instalación según origen ─────────────────────────────
    if [ "$ORIGEN" = "FTP" ]; then
        navegar_ftp_y_seleccionar || { echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1; }
        local dest_pkg="/tmp/${ARCHIVO_SELECCIONADO}"
        descargar_y_validar_hash "$RUTA_FTP_ARCHIVO" "$dest_pkg" || { echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1; }
        echo -e "${BLUE}[*] Instalando $ARCHIVO_SELECCIONADO...${NC}"
        dnf install -y -q "$dest_pkg" &>/dev/null || dnf install -y -q nginx &>/dev/null
        rm -f "$dest_pkg"
    else
        # Mismo flujo de práctica 6
        if rpm -q nginx &>/dev/null; then
            echo -e "${YELLOW}[!] Nginx ya está instalado en el sistema.${NC}"
            echo -ne "${YELLOW}¿Deseas reinstalarlo? (s/n): ${NC}"
            read resp
            if [[ ! "$resp" =~ ^[sS]$ ]]; then
                echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return
            fi
            systemctl stop nginx &>/dev/null
            dnf remove -y -q nginx nginx-filesystem &>/dev/null
        fi

        if [ ! -f /etc/yum.repos.d/nginx.repo ]; then
            cat > /etc/yum.repos.d/nginx.repo << 'REPOEOF'
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
REPOEOF
            rpm --import https://nginx.org/keys/nginx_signing.key &>/dev/null || true
            dnf clean all &>/dev/null && dnf makecache &>/dev/null
        fi

        echo -e "${BLUE}[*] Consultando versiones disponibles de 'nginx'...${NC}"
        mapfile -t TODAS < <(
            dnf list --showduplicates nginx 2>/dev/null \
                | awk 'NF>=3 && $1~/^nginx\./ { print $2 }' \
                | sed 's/^[0-9]*://' \
                | grep -oP '^[0-9]+\.[0-9]+\.[0-9]+' \
                | sort -uV
        )

        local VERSIONES=()
        local n=${#TODAS[@]}
        if   [ "$n" -ge 3 ]; then VERSIONES=("${TODAS[0]}" "${TODAS[$((n-2))]}" "${TODAS[$((n-1))]}")
        elif [ "$n" -eq 2 ]; then VERSIONES=("${TODAS[0]}" "${TODAS[1]}")
        elif [ "$n" -eq 1 ]; then VERSIONES=("${TODAS[0]}")
        else                      VERSIONES=("latest")
        fi

        echo ""
        echo -e "${CYAN}--- Versiones disponibles para nginx ---${NC}"
        local total=${#VERSIONES[@]}
        for i in "${!VERSIONES[@]}"; do
            local num=$((i+1)) v="${VERSIONES[$i]}"
            if   [ "$num" -eq "$total" ];      then echo -e "  $num) $v  ${GREEN}[Latest]${NC}"
            elif [ "$num" -eq $((total-1)) ];  then echo -e "  $num) $v  ${CYAN}[LTS / Estable]${NC}"
            else                                    echo -e "  $num) $v  ${BLUE}[Anterior]${NC}"
            fi
        done
        echo ""

        local sel=""
        while true; do
            echo -ne "${YELLOW}Selecciona una versión [1-${total}]: ${NC}"
            read sel
            if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "$total" ]; then break; fi
            echo -e "${RED}[!] Selección inválida.${NC}"
        done
        local ver="${VERSIONES[$((sel-1))]}"

        echo -e "${BLUE}[*] Instalando Nginx silenciosamente...${NC}"
        if [ "$ver" = "latest" ]; then
            dnf install -y -q nginx &>/dev/null
        else
            dnf install -y -q "nginx-${ver}" &>/dev/null || dnf install -y -q nginx &>/dev/null
        fi
    fi

    # ── Configuración común ──────────────────────────────────
    local ver_real
    ver_real=$(nginx -v 2>&1 | grep -oP 'nginx/\K[\d.]+' || echo "desconocida")

    local NGINX_WEB="/var/www/nginx"
    mkdir -p "$NGINX_WEB"
    chown -R nginx:nginx "$NGINX_WEB"
    chmod 755 "$NGINX_WEB"

    # nginx.conf principal (igual a práctica 6)
    cat > /etc/nginx/nginx.conf << 'MAINNGINX'
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /run/nginx.pid;

events { worker_connections 1024; }

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    access_log /var/log/nginx/access.log main;
    sendfile on;
    keepalive_timeout 65;
    include /etc/nginx/conf.d/*.conf;
}
MAINNGINX

    # Eliminar TODOS los .conf que puedan tener listen en conflicto
    rm -f /etc/nginx/conf.d/default.conf
    rm -f /etc/nginx/conf.d/practica6.conf
    # Deshabilitar cualquier conf residual de instalaciones previas
    for f in /etc/nginx/conf.d/*.conf; do
        [[ "$f" == */practica7.conf ]] && continue
        mv "$f" "${f}.disabled" 2>/dev/null
    done

    preguntar_ssl
    pedir_puerto "HTTP"
    local puerto_http="$PUERTO_SELECCIONADO"

    if [ "$ACTIVAR_SSL" = "yes" ]; then
        verificar_o_generar_cert
        pedir_puerto "HTTPS"
        local puerto_https="$PUERTO_SELECCIONADO"
        configurar_firewall "$puerto_https" "nginx"

        cat > /etc/nginx/conf.d/practica7.conf << EOF
# ── HTTP → HTTPS ──
server {
    listen      ${puerto_http};
    server_name ${DOMAIN} _;
    return 301  https://\$server_addr:${puerto_https}\$request_uri;
}

# ── HTTPS ──
server {
    listen      ${puerto_https} ssl;
    server_name ${DOMAIN} _;
    root        ${NGINX_WEB};
    index       index.html;

    ssl_certificate     ${CERT_FILE};
    ssl_certificate_key ${KEY_FILE};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    server_tokens off;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options            "SAMEORIGIN"                        always;
    add_header X-Content-Type-Options     "nosniff"                           always;
    add_header X-XSS-Protection           "1; mode=block"                     always;
    add_header Referrer-Policy            "strict-origin-when-cross-origin"   always;

    if (\$request_method !~ ^(GET|POST|HEAD)$) { return 405; }

    location / { try_files \$uri \$uri/ =404; }

    access_log /var/log/nginx/ssl_access.log;
    error_log  /var/log/nginx/ssl_error.log;
}
EOF
        echo -e "${GREEN}[+] SSL configurado: HTTP $puerto_http → HTTPS $puerto_https.${NC}"
    else
        cat > /etc/nginx/conf.d/practica7.conf << EOF
server {
    listen      ${puerto_http};
    server_name ${DOMAIN} _;
    root        ${NGINX_WEB};
    index       index.html;

    server_tokens off;
    add_header X-Frame-Options        "SAMEORIGIN"                      always;
    add_header X-Content-Type-Options "nosniff"                         always;
    add_header X-XSS-Protection       "1; mode=block"                   always;
    add_header Referrer-Policy        "strict-origin-when-cross-origin" always;

    if (\$request_method !~ ^(GET|POST|HEAD)$) { return 405; }

    location / { try_files \$uri \$uri/ =404; }
}
EOF
    fi

    crear_index "$NGINX_WEB" "Nginx" "$ver_real" "$puerto_http" "$ACTIVAR_SSL"
    chown nginx:nginx "$NGINX_WEB/index.html"
    chmod 644 "$NGINX_WEB/index.html"

    configurar_firewall "$puerto_http" "nginx"
    systemctl enable nginx &>/dev/null

    # Asegurar permisos correctos del pid file (SELinux a veces lo bloquea)
    mkdir -p /run
    touch /run/nginx.pid 2>/dev/null
    chown root:root /run/nginx.pid 2>/dev/null
    chmod 644 /run/nginx.pid 2>/dev/null

    # Validar config
    if ! nginx -t 2>/dev/null; then
        echo -e "${RED}[-] Error en la configuración de Nginx:${NC}"
        nginx -t
        echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1
    fi

    # Reiniciar y verificar que levantó
    systemctl restart nginx
    sleep 2
    if ! systemctl is-active --quiet nginx; then
        echo -e "${RED}[-] Nginx no levantó. Log de error:${NC}"
        journalctl -u nginx -n 20 --no-pager
        echo -e "${YELLOW}[!] Intentando con nginx -s reload...${NC}"
        nginx -s reload 2>/dev/null || nginx
        sleep 2
        systemctl is-active --quiet nginx && \
            echo -e "${GREEN}[+] Nginx levantó con reload.${NC}" || \
            echo -e "${RED}[-] Nginx sigue sin responder.${NC}"
    fi

    echo -e "${GREEN}${BOLD}[+] Nginx configurado correctamente en el puerto $puerto_http.${NC}"
    [ "$ACTIVAR_SSL" = "yes" ] && \
        echo -e "${GREEN}${BOLD}[+] HTTPS activo en puerto $puerto_https.${NC}"
    echo -ne "\n${BLUE}Presiona Enter...${NC}"; read
}

# ============================================================
# TOMCAT
# ============================================================

function obtener_versiones_tomcat() {
    TOMCAT_V9=$(curl -s --max-time 8 "https://downloads.apache.org/tomcat/tomcat-9/" 2>/dev/null | grep -oP 'v\K9\.[0-9]+\.[0-9]+' | sort -V | tail -1)
    TOMCAT_LTS=$(curl -s --max-time 8 "https://downloads.apache.org/tomcat/tomcat-10/" 2>/dev/null | grep -oP 'v\K10\.1\.[0-9]+' | sort -V | tail -1)
    TOMCAT_LATEST=$(curl -s --max-time 8 "https://downloads.apache.org/tomcat/tomcat-11/" 2>/dev/null | grep -oP 'v\K11\.[0-9]+\.[0-9]+' | sort -V | tail -1)
    TOMCAT_V9="${TOMCAT_V9:-9.0.102}"
    TOMCAT_LTS="${TOMCAT_LTS:-10.1.40}"
    TOMCAT_LATEST="${TOMCAT_LATEST:-11.0.5}"
}

function instalar_tomcat() {
    clear
    echo -e "${CYAN}--- Instalación de Apache Tomcat - Práctica 7 ---${NC}"

    elegir_origen

    local tc_tar="" tc_ver=""

    if [ "$ORIGEN" = "FTP" ]; then
        # ── Desde FTP ────────────────────────────────────────
        navegar_ftp_y_seleccionar || { echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1; }
        tc_tar="/tmp/${ARCHIVO_SELECCIONADO}"
        descargar_y_validar_hash "$RUTA_FTP_ARCHIVO" "$tc_tar" || { echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1; }
        # Deducir versión del nombre de archivo
        tc_ver=$(echo "$ARCHIVO_SELECCIONADO" | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1)
        tc_ver="${tc_ver:-desconocida}"
    else
        # ── Desde WEB (igual a práctica 6) ──────────────────
        if [ -d "/opt/tomcat" ]; then
            echo -e "${YELLOW}[!] Tomcat ya está instalado en /opt/tomcat.${NC}"
            echo -ne "${YELLOW}¿Deseas reinstalarlo? (s/n): ${NC}"
            read resp
            if [[ ! "$resp" =~ ^[sS]$ ]]; then
                echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return
            fi
            systemctl stop tomcat &>/dev/null
            systemctl disable tomcat &>/dev/null
            rm -f /etc/systemd/system/tomcat.service
            systemctl daemon-reload &>/dev/null
            rm -rf /opt/tomcat
        fi

        # Limpiar capabilities residuales en Java
        local java_bin_prev
        java_bin_prev=$(readlink -f "$(which java)" 2>/dev/null)
        if [ -n "$java_bin_prev" ]; then
            setcap -r "$java_bin_prev" 2>/dev/null || true
            echo -e "${BLUE}[*] Limpiando capabilities residuales en el binario Java...${NC}"
        fi

        echo -e "${BLUE}[*] Instalando Java...${NC}"
        dnf install -y -q java-17-openjdk-headless &>/dev/null

        if ! command -v java &>/dev/null; then
            echo -e "${RED}[-] Error: Java no se instaló correctamente.${NC}"
            echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1
        fi

        echo -e "${BLUE}[*] Consultando versiones disponibles de Tomcat...${NC}"
        obtener_versiones_tomcat

        echo ""
        echo -e "${CYAN}--- Versiones disponibles para Tomcat ---${NC}"
        echo -e "  1) $TOMCAT_V9      ${BLUE}[Rama 9 - Compatible]${NC}"
        echo -e "  2) $TOMCAT_LTS     ${CYAN}[LTS / Estable]${NC}"
        echo -e "  3) $TOMCAT_LATEST  ${GREEN}[Latest]${NC}"
        echo ""

        local sel=""
        while true; do
            echo -ne "${YELLOW}Selecciona una versión [1-3]: ${NC}"
            read sel
            if [[ "$sel" =~ ^[1-3]$ ]]; then break; fi
            echo -e "${RED}[!] Selección inválida.${NC}"
        done

        case "$sel" in
            1) tc_ver="$TOMCAT_V9"     ;;
            2) tc_ver="$TOMCAT_LTS"    ;;
            3) tc_ver="$TOMCAT_LATEST" ;;
        esac
        local tc_major
        tc_major=$(echo "$tc_ver" | cut -d. -f1)

        local tc_url="https://downloads.apache.org/tomcat/tomcat-${tc_major}/v${tc_ver}/bin/apache-tomcat-${tc_ver}.tar.gz"
        tc_tar="/tmp/tomcat.tar.gz"

        echo -e "${BLUE}[*] Descargando Tomcat $tc_ver...${NC}"
        if ! curl -L -f -s --max-time 180 -o "$tc_tar" "$tc_url"; then
            echo -e "${RED}[-] Error al descargar Tomcat desde: $tc_url${NC}"
            echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1
        fi

        if ! tar -tzf "$tc_tar" &>/dev/null; then
            echo -e "${RED}[-] El archivo descargado está corrupto o incompleto.${NC}"
            rm -f "$tc_tar"
            echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1
        fi
    fi

    # ── Instalación y configuración comunes ──────────────────
    local tc_dir="/opt/tomcat"

    # Si viene de FTP y ya existía, limpiar antes
    if [ -d "$tc_dir" ] && [ "$ORIGEN" = "FTP" ]; then
        systemctl stop tomcat &>/dev/null
        systemctl disable tomcat &>/dev/null
        rm -f /etc/systemd/system/tomcat.service
        systemctl daemon-reload &>/dev/null
        rm -rf "$tc_dir"
        dnf install -y -q java-17-openjdk-headless &>/dev/null
    fi

    echo -e "${BLUE}[*] Extrayendo Tomcat...${NC}"
    mkdir -p "$tc_dir"
    tar -xzf "$tc_tar" -C "$tc_dir" --strip-components=1
    rm -f "$tc_tar"

    if ! id "tomcat" &>/dev/null; then
        useradd -r -s /sbin/nologin -d "$tc_dir" tomcat &>/dev/null
    fi

    rm -rf "$tc_dir/webapps/"*

    preguntar_ssl
    pedir_puerto "HTTP (Tomcat)"
    local puerto="$PUERTO_SELECCIONADO"

    sed -i "s/port=\"8080\"/port=\"$puerto\"/" "$tc_dir/conf/server.xml"
    echo -e "${BLUE}[*] Puerto $puerto configurado en server.xml.${NC}"

    # Cabeceras de seguridad en web.xml (igual a práctica 6)
    python3 - "$tc_dir/conf/web.xml" << 'PYEOF'
import sys
path = sys.argv[1]
with open(path, 'r') as f:
    content = f.read()

insert = """    <filter>
        <filter-name>httpHeaderSecurity</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>antiClickJackingOption</param-name>
            <param-value>SAMEORIGIN</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>httpHeaderSecurity</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
"""
if '</web-app>' in content:
    content = content.replace('</web-app>', insert + '</web-app>')
    with open(path, 'w') as f:
        f.write(content)
    print("[*] web.xml actualizado con cabeceras de seguridad.")
else:
    print("[!] No se encontró </web-app> en web.xml, se omite el parche.")
PYEOF

    # Resolver JAVA_HOME (idéntico a práctica 6)
    local java_bin
    java_bin=$(readlink -f "$(which java)")
    local java_home
    java_home=$(dirname "$(dirname "$java_bin")")
    if [ ! -d "$java_home" ]; then
        java_home=$(find /usr/lib/jvm -maxdepth 1 -name "java-17*" -type d | head -1)
    fi

    local libjli_path
    libjli_path=$(find "$java_home" -name "libjli.so" 2>/dev/null | head -1)
    local jli_dir=""
    if [ -n "$libjli_path" ]; then
        jli_dir=$(dirname "$libjli_path")
        echo -e "${BLUE}[*] libjli.so encontrado en: $jli_dir${NC}"
    fi

    # ── SSL para Tomcat ──────────────────────────────────────
    if [ "$ACTIVAR_SSL" = "yes" ]; then
        verificar_o_generar_cert
        pedir_puerto "HTTPS (Tomcat)"
        local puerto_https="$PUERTO_SELECCIONADO"
        configurar_firewall "$puerto_https"

        # Convertir PEM → PKCS12 para Java
        # -legacy forzado: OpenSSL 3.x genera AES-256 por defecto que
        # Java 17 puede rechazar; -legacy usa RC2/3DES compatible con JKS
        local p12_file="$tc_dir/conf/reprobados.p12"   # DENTRO de tc_dir → sin problemas de SELinux
        openssl pkcs12 -export -legacy \
            -in "$CERT_FILE" -inkey "$KEY_FILE" \
            -out "$p12_file" -name reprobados \
            -passout pass:changeit 2>/dev/null

        # Fallback si -legacy no está disponible (OpenSSL < 3)
        if [ ! -s "$p12_file" ]; then
            openssl pkcs12 -export \
                -in "$CERT_FILE" -inkey "$KEY_FILE" \
                -out "$p12_file" -name reprobados \
                -passout pass:changeit 2>/dev/null
        fi

        # Permisos ANTES de que Tomcat intente leer el archivo
        chmod 640 "$p12_file"
        chown tomcat:tomcat "$p12_file" 2>/dev/null || true

        # Verificar que el p12 es legible por Java con keytool
        if command -v keytool &>/dev/null; then
            if keytool -list -keystore "$p12_file" -storetype PKCS12 \
               -storepass changeit &>/dev/null; then
                echo -e "${GREEN}[+] PKCS12 verificado con keytool: OK.${NC}"
            else
                echo -e "${RED}[-] keytool no puede leer el PKCS12. Reintentando sin -legacy...${NC}"
                openssl pkcs12 -export \
                    -in "$CERT_FILE" -inkey "$KEY_FILE" \
                    -out "$p12_file" -name reprobados \
                    -passout pass:changeit 2>/dev/null
                chmod 640 "$p12_file"
                chown tomcat:tomcat "$p12_file" 2>/dev/null || true
            fi
        fi

        # Agregar conector HTTPS en server.xml detectando versión de Tomcat
        python3 - "$tc_dir/conf/server.xml" "$puerto" "$puerto_https" "$p12_file" "$tc_ver" << 'PYEOF'
import sys, re

path   = sys.argv[1]
ph     = sys.argv[2]   # puerto HTTP
phs    = sys.argv[3]   # puerto HTTPS
p12    = sys.argv[4]   # ruta al .p12
tc_ver = sys.argv[5]   # versión de Tomcat, ej. "9.0.115" o "10.1.52"

with open(path) as f:
    content = f.read()

# Actualizar redirectPort al nuevo puerto HTTPS
content = re.sub(r'redirectPort="\d+"', f'redirectPort="{phs}"', content)

# Detectar versión mayor
try:
    major = int(tc_ver.split('.')[0])
except Exception:
    major = 10   # asumir moderno si no se puede parsear

if major >= 10:
    # Tomcat 10 y 11 → SSLHostConfig + Certificate (sintaxis moderna)
    https_connector = f"""
    <!-- Conector HTTPS - Practica 7 -->
    <Connector port="{phs}"
               protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150"
               SSLEnabled="true"
               scheme="https"
               secure="true">
        <SSLHostConfig protocols="TLSv1.2+TLSv1.3">
            <Certificate certificateKeystoreFile="{p12}"
                         certificateKeystorePassword="changeit"
                         certificateKeystoreType="PKCS12"
                         type="RSA"/>
        </SSLHostConfig>
    </Connector>
"""
else:
    # Tomcat 9 → atributos inline en el Connector (sintaxis clásica)
    https_connector = f"""
    <!-- Conector HTTPS - Practica 7 -->
    <Connector port="{phs}"
               protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150"
               SSLEnabled="true"
               scheme="https"
               secure="true"
               keystoreFile="{p12}"
               keystorePass="changeit"
               keystoreType="PKCS12"
               clientAuth="false"
               sslProtocol="TLS"
               sslEnabledProtocols="TLSv1.2,TLSv1.3"/>
"""

# Solo insertar si el conector HTTPS aun no existe
if f'port="{phs}"' not in content:
    content = content.replace('</Service>', https_connector + '</Service>')
    with open(path, 'w') as f:
        f.write(content)
    print(f"[+] Conector HTTPS (Tomcat {major}.x) en puerto {phs} agregado a server.xml.")
else:
    print(f"[!] Ya existe un conector en puerto {phs}, se omite insercion.")
PYEOF
        echo -e "${GREEN}[+] SSL configurado en Tomcat, puerto HTTPS: $puerto_https.${NC}"
    fi

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
    crear_index "$tc_dir/webapps/ROOT" "Apache Tomcat" "$tc_ver" "$puerto" "$ACTIVAR_SSL"

    chown -R tomcat:tomcat "$tc_dir"
    chmod 755 "$tc_dir"
    chmod 750 "$tc_dir/conf"
    chmod +x "$tc_dir/bin/"*.sh

    configurar_firewall "$puerto"
    [ "$ACTIVAR_SSL" = "yes" ] && configurar_firewall "$puerto_https"

    # ── authbind y User para puertos < 1024 ─────────────────
    # NOTA: authbind con --deep NO intercepta socketChannel.bind()
    # que usa Java internamente para abrir conectores Tomcat.
    # La unica solución fiable para puertos < 1024 es User=root.
    local svc_user="tomcat"
    local svc_group="tomcat"
    local usar_authbind="no"

    local puerto_http_privilegiado="no"
    local puerto_https_privilegiado="no"
    [ "$puerto" -lt 1024 ]                                       && puerto_http_privilegiado="yes"
    [ "$ACTIVAR_SSL" = "yes" ] && [ "$puerto_https" -lt 1024 ]  && puerto_https_privilegiado="yes"

    if [ "$puerto_http_privilegiado" = "yes" ] || [ "$puerto_https_privilegiado" = "yes" ]; then
        svc_user="root"
        svc_group="root"
        echo -e "${YELLOW}[!] Puertos privilegiados (<1024) detectados: Tomcat correrá como root.${NC}"
    fi

    local exec_start="${tc_dir}/bin/startup.sh"

    cat > /etc/systemd/system/tomcat.service << SYSDEOF
[Unit]
Description=Apache Tomcat ${tc_ver}
After=network.target

[Service]
Type=forking
User=${svc_user}
Group=${svc_group}
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

    echo -e "${BLUE}[*] Iniciando Tomcat (espera hasta 30 seg)...${NC}"
    systemctl start tomcat

    # Esperar hasta 30 segundos a que Tomcat levante
    local intentos=0
    while [ $intentos -lt 30 ]; do
        sleep 1
        intentos=$((intentos + 1))
        [ $((intentos % 5)) -eq 0 ] && echo -e "${BLUE}[*] Esperando... ${intentos}s${NC}"
        if ss -tlnp 2>/dev/null | grep -q ":${puerto} "; then
            break
        fi
    done

    if systemctl is-active --quiet tomcat; then
        echo -e "${GREEN}${BOLD}[+] Tomcat configurado y ejecutándose en el puerto $puerto.${NC}"
        if [ "$ACTIVAR_SSL" = "yes" ]; then
            # Esperar un poco más para que el conector HTTPS también levante
            sleep 3
            if ss -tlnp 2>/dev/null | grep -q ":${puerto_https} "; then
                echo -e "${GREEN}${BOLD}[+] HTTPS activo y escuchando en puerto $puerto_https.${NC}"
            else
                echo -e "${RED}[-] Tomcat corre pero el puerto HTTPS $puerto_https NO está escuchando.${NC}"
                echo -e "${YELLOW}[!] Últimas líneas de catalina.out:${NC}"
                tail -30 "$tc_dir/logs/catalina.out" 2>/dev/null | grep -i "ssl\|tls\|keystore\|certificate\|error\|exception" || \
                    tail -15 "$tc_dir/logs/catalina.out" 2>/dev/null
            fi
        fi
    else
        echo -e "${RED}[-] Tomcat no inició correctamente.${NC}"
        journalctl -u tomcat -n 20 --no-pager
        echo ""
        echo -e "${YELLOW}[!] Log de Catalina:${NC}"
        tail -30 "$tc_dir/logs/catalina.out" 2>/dev/null || echo "(sin log disponible)"
    fi

    echo -ne "\n${BLUE}Presiona Enter...${NC}"; read
}

# ============================================================
# VSFTPD
# ============================================================

function instalar_vsftpd() {
    clear
    echo -e "${CYAN}--- Instalación de vsftpd (FTP/FTPS) - Práctica 7 ---${NC}"

    elegir_origen

    if [ "$ORIGEN" = "FTP" ]; then
        navegar_ftp_y_seleccionar || { echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1; }
        local dest_pkg="/tmp/${ARCHIVO_SELECCIONADO}"
        descargar_y_validar_hash "$RUTA_FTP_ARCHIVO" "$dest_pkg" || { echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1; }
        echo -e "${BLUE}[*] Instalando $ARCHIVO_SELECCIONADO...${NC}"
        dnf install -y -q "$dest_pkg" &>/dev/null || dnf install -y -q vsftpd &>/dev/null
        rm -f "$dest_pkg"
    else
        if rpm -q vsftpd &>/dev/null; then
            echo -e "${YELLOW}[!] vsftpd ya está instalado en el sistema.${NC}"
            echo -ne "${YELLOW}¿Deseas reinstalarlo? (s/n): ${NC}"
            read resp
            if [[ ! "$resp" =~ ^[sS]$ ]]; then
                echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return
            fi
            systemctl stop vsftpd &>/dev/null
            dnf remove -y -q vsftpd &>/dev/null
        fi
        echo -e "${BLUE}[*] Instalando vsftpd...${NC}"
        dnf install -y -q vsftpd &>/dev/null || {
            echo -e "${RED}[-] Error instalando vsftpd.${NC}"
            echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1
        }
    fi

    preguntar_ssl

    # ── Usuario y estructura del repositorio FTP ─────────────
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

    # Crear estructura /http/[OS]/[Servicio]
    for os in Linux Windows; do
        for srv in Apache Nginx Tomcat vsftpd; do
            mkdir -p "$ftp_home/http/$os/$srv"
        done
    done
    chown -R "$ftp_user":"$ftp_user" "$ftp_home"

    # ── Firewall y SELinux para FTP ──────────────────────────
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-service=ftp &>/dev/null
        firewall-cmd --permanent --add-port=40000-40100/tcp &>/dev/null
        firewall-cmd --reload &>/dev/null
        echo -e "${BLUE}[*] Firewall: FTP y puertos pasivos habilitados.${NC}"
    fi
    if command -v setsebool &>/dev/null; then
        setsebool -P allow_ftpd_full_access 1 &>/dev/null
        setsebool -P ftpd_use_passive_mode  1 &>/dev/null
        echo -e "${BLUE}[*] SELinux: booleans FTP activados.${NC}"
    fi

    # Backup de configuración original
    cp /etc/vsftpd/vsftpd.conf /etc/vsftpd/vsftpd.conf.bak 2>/dev/null

    local local_ip
    local_ip=$(hostname -I | awk '{print $1}')

    if [ "$ACTIVAR_SSL" = "yes" ]; then
        # Generar certificado dedicado para FTPS
        local ftps_cert="/etc/vsftpd/vsftpd.pem"
        local ftps_key="/etc/vsftpd/vsftpd.key"
        echo -e "${BLUE}[*] Generando certificado SSL para FTPS...${NC}"
        mkdir -p /etc/vsftpd
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$ftps_key" \
            -out    "$ftps_cert" \
            -subj   "/C=MX/ST=Sinaloa/L=Culiacan/O=Reprobados/OU=FTP/CN=${DOMAIN}" \
            2>/dev/null
        chmod 600 "$ftps_key" "$ftps_cert"
        echo -e "${GREEN}[+] Certificado FTPS generado.${NC}"

        cat > /etc/vsftpd/vsftpd.conf << EOF
# ── vsftpd - Práctica 7 (FTPS) ──────────────────────────────
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

# Lista blanca de usuarios
userlist_enable=YES
userlist_deny=NO
userlist_file=/etc/vsftpd/user_list

# ── Modo Pasivo ──────────────────────────────────────────────
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
pasv_address=${local_ip}

# ── FTPS (SSL Explícito - RFC 4217) ─────────────────────────
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

# ── Logs ─────────────────────────────────────────────────────
xferlog_file=/var/log/vsftpd.log
EOF
        echo -e "${GREEN}[+] FTPS (SSL explícito) configurado.${NC}"
    else
        cat > /etc/vsftpd/vsftpd.conf << EOF
# ── vsftpd - Práctica 7 (FTP sin SSL) ───────────────────────
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

    if ! systemctl restart vsftpd; then
        echo -e "${RED}[-] Error al iniciar vsftpd. Revisa el log:${NC}"
        journalctl -u vsftpd -n 15 --no-pager
        echo -ne "\n${BLUE}Presiona Enter...${NC}"; read; return 1
    fi

    echo -e "${GREEN}${BOLD}[+] vsftpd configurado correctamente.${NC}"
    echo ""
    echo -e "${CYAN}--- Información del repositorio FTP ---${NC}"
    echo -e "  Host:      ${local_ip}"
    echo -e "  Puerto:    21"
    echo -e "  Usuario:   ${ftp_user}"
    echo -e "  Password:  FTP@Practica7!"
    echo -e "  Raíz:      ${ftp_home}"
    echo -e "  FTPS/SSL:  ${ACTIVAR_SSL}"
    [ "$ACTIVAR_SSL" = "yes" ] && \
        echo -e "  Cert:      /etc/vsftpd/vsftpd.pem"
    echo -ne "\n${BLUE}Presiona Enter...${NC}"; read
}

# ============================================================
# VERIFICACIÓN GLOBAL
# ============================================================

function verificar_todos_servicios() {
    clear
    echo -e "${CYAN}===================================================${NC}"
    echo -e "${GREEN}${BOLD}     RESUMEN DE VERIFICACIÓN DE SERVICIOS          ${NC}"
    echo -e "${CYAN}===================================================${NC}"
    echo ""

    _check_servicio "Apache (httpd)" "httpd" \
        "/etc/httpd/conf.d/ssl_reprobados.conf" \
        "$(ss -tlnp | grep httpd | awk '{print $4}' | grep -oP ':\K\d+' | head -1)"

    _check_servicio "Nginx" "nginx" \
        "/etc/nginx/conf.d/practica7.conf" \
        "$(grep -oP '(?<=listen\s)\d+(?=;)' /etc/nginx/conf.d/practica7.conf 2>/dev/null | head -1)"

    _check_servicio_tomcat

    _check_vsftpd

    echo ""
    echo -e "${YELLOW}── Certificado SSL (${DOMAIN}) ──${NC}"
    if [ -f "$CERT_FILE" ]; then
        local exp cn
        exp=$(openssl x509 -noout -enddate  -in "$CERT_FILE" 2>/dev/null | cut -d= -f2)
        cn=$(openssl  x509 -noout -subject  -in "$CERT_FILE" 2>/dev/null | grep -oP 'CN\s*=\s*\K[^,/]+')
        echo -e "  Archivo:  $CERT_FILE"
        echo -e "  CN:       $cn"
        echo -e "  Expira:   $exp"
    else
        echo -e "  ${YELLOW}[!] Certificado no generado aún.${NC}"
    fi

    echo ""
    echo -ne "${BLUE}Presiona Enter para continuar...${NC}"; read
}

function _check_servicio() {
    local nombre=$1 servicio=$2 conf_ssl=$3 puerto_http=$4
    echo -e "${YELLOW}── $nombre ──${NC}"
    if systemctl is-active --quiet "$servicio" 2>/dev/null; then
        echo -e "  Estado:      ${GREEN}✓ ACTIVO${NC}"
        echo -e "  Puerto HTTP: ${puerto_http:-no detectado}"
        if [ -f "$conf_ssl" ]; then
            local puerto_https
            puerto_https=$(grep -oP '(?<=\*:)\d+' "$conf_ssl" 2>/dev/null | tail -1)
            echo -e "  Puerto HTTPS: ${puerto_https:-no detectado}"
            _verificar_ssl_con_openssl "$puerto_https" "$nombre"
        else
            echo -e "  SSL: ${YELLOW}No configurado${NC}"
        fi
    else
        echo -e "  Estado: ${RED}✗ INACTIVO${NC}"
    fi
    echo ""
}

function _check_servicio_tomcat() {
    echo -e "${YELLOW}── Apache Tomcat ──${NC}"
    if systemctl is-active --quiet tomcat 2>/dev/null; then
        echo -e "  Estado: ${GREEN}✓ ACTIVO${NC}"
        local puerto_http puerto_https
        puerto_http=$(grep -oP 'port="\K\d+(?="[^>]*protocol)' /opt/tomcat/conf/server.xml 2>/dev/null | head -1)
        puerto_https=$(grep -oP 'port="\K\d+(?="[^>]*SSLEnabled)' /opt/tomcat/conf/server.xml 2>/dev/null | head -1)
        echo -e "  Puerto HTTP:  ${puerto_http:-no detectado}"
        if [ -n "$puerto_https" ]; then
            echo -e "  Puerto HTTPS: $puerto_https"
            _verificar_ssl_con_openssl "$puerto_https" "Tomcat"
        else
            echo -e "  SSL: ${YELLOW}No configurado${NC}"
        fi
    else
        echo -e "  Estado: ${RED}✗ INACTIVO${NC}"
    fi
    echo ""
}

function _check_vsftpd() {
    echo -e "${YELLOW}── vsftpd (FTP/FTPS) ──${NC}"
    if systemctl is-active --quiet vsftpd 2>/dev/null; then
        echo -e "  Estado: ${GREEN}✓ ACTIVO${NC}"
        echo -e "  Puerto: 21 (control)"
        if grep -q "ssl_enable=YES" /etc/vsftpd/vsftpd.conf 2>/dev/null; then
            echo -e "  FTPS:   ${GREEN}Habilitado (SSL explícito)${NC}"
        else
            echo -e "  FTPS:   ${YELLOW}No configurado${NC}"
        fi
    else
        echo -e "  Estado: ${RED}✗ INACTIVO${NC}"
    fi
    echo ""
}

function _verificar_ssl_con_openssl() {
    local puerto=$1 servicio=$2
    [ -z "$puerto" ] && return
    local ip
    ip=$(hostname -I | awk '{print $1}')
    local resultado
    resultado=$(echo | timeout 5 openssl s_client \
        -connect "${ip}:${puerto}" \
        -servername "$DOMAIN" 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$resultado" ]; then
        echo -e "  ${GREEN}✓ SSL OK: $resultado${NC}"
    else
        echo -e "  ${RED}✗ SSL no responde en ${ip}:${puerto}${NC}"
    fi
}