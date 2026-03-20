#!/bin/bash
# ============================================================
# setup_ftp_repo.sh - Prepara el repositorio FTP
# Ejecutar en el servidor vsftpd ANTES del orquestador
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-] Ejecuta como root.${NC}"; exit 1
fi

FTP_ROOT="/srv/ftp/repo"
FTP_USER="ftpuser"

echo -e "${CYAN}===================================================${NC}"
echo -e "${GREEN}${BOLD}  Setup Repositorio FTP - Práctica 7              ${NC}"
echo -e "${CYAN}===================================================${NC}"

# ── Crear usuario si no existe ────────────────────────────────
if ! id "$FTP_USER" &>/dev/null; then
    useradd -m -d "$FTP_ROOT" -s /sbin/nologin "$FTP_USER" &>/dev/null
    echo "ftpuser:FTP@Practica7!" | chpasswd
    echo -e "${GREEN}[+] Usuario '$FTP_USER' creado.${NC}"
fi

# ── Crear estructura de directorios ──────────────────────────
for OS in Linux Windows; do
    for SRV in Apache Nginx Tomcat vsftpd; do
        mkdir -p "${FTP_ROOT}/http/${OS}/${SRV}"
    done
done
echo -e "${GREEN}[+] Estructura de directorios creada.${NC}"

# ── Descargar / generar instaladores ─────────────────────────

# Helper: genera un placeholder con su sha256
function hacer_placeholder() {
    local path=$1 contenido=$2
    echo "$contenido" > "$path"
    sha256sum "$path" | awk '{print $1}' > "${path}.sha256"
    echo -e "${YELLOW}  [placeholder] $(basename $path)${NC}"
}

# -- Apache para Linux --
APACHE_DIR="${FTP_ROOT}/http/Linux/Apache"
APACHE_PKG="httpd-2.4.62-1.el9.x86_64.rpm"
if [ ! -f "${APACHE_DIR}/${APACHE_PKG}" ]; then
    echo -e "${BLUE}[*] Intentando descargar Apache RPM...${NC}"
    APACHE_URL="https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/Packages/h/${APACHE_PKG}"
    if curl -L -f -s --max-time 60 -o "${APACHE_DIR}/${APACHE_PKG}" "$APACHE_URL" 2>/dev/null; then
        sha256sum "${APACHE_DIR}/${APACHE_PKG}" | awk '{print $1}' > "${APACHE_DIR}/${APACHE_PKG}.sha256"
        echo -e "${GREEN}  [+] Apache RPM descargado.${NC}"
    else
        hacer_placeholder "${APACHE_DIR}/${APACHE_PKG}" "placeholder-apache-2.4.62"
    fi
fi

# -- Nginx para Linux --
NGINX_DIR="${FTP_ROOT}/http/Linux/Nginx"
NGINX_PKG="nginx-1.26.2-1.el9.ngx.x86_64.rpm"
if [ ! -f "${NGINX_DIR}/${NGINX_PKG}" ]; then
    echo -e "${BLUE}[*] Intentando descargar Nginx RPM...${NC}"
    NGINX_URL="https://nginx.org/packages/centos/9/x86_64/RPMS/${NGINX_PKG}"
    if curl -L -f -s --max-time 60 -o "${NGINX_DIR}/${NGINX_PKG}" "$NGINX_URL" 2>/dev/null; then
        sha256sum "${NGINX_DIR}/${NGINX_PKG}" | awk '{print $1}' > "${NGINX_DIR}/${NGINX_PKG}.sha256"
        echo -e "${GREEN}  [+] Nginx RPM descargado.${NC}"
    else
        hacer_placeholder "${NGINX_DIR}/${NGINX_PKG}" "placeholder-nginx-1.26.2"
    fi
fi

# -- Tomcat para Linux --
TOMCAT_DIR="${FTP_ROOT}/http/Linux/Tomcat"
TC_VER="10.1.40"
TC_PKG="apache-tomcat-${TC_VER}.tar.gz"
if [ ! -f "${TOMCAT_DIR}/${TC_PKG}" ]; then
    echo -e "${BLUE}[*] Descargando Tomcat ${TC_VER}...${NC}"
    TC_URL="https://downloads.apache.org/tomcat/tomcat-10/v${TC_VER}/bin/${TC_PKG}"
    if curl -L -f -s --max-time 120 -o "${TOMCAT_DIR}/${TC_PKG}" "$TC_URL" 2>/dev/null; then
        sha256sum "${TOMCAT_DIR}/${TC_PKG}" | awk '{print $1}' > "${TOMCAT_DIR}/${TC_PKG}.sha256"
        echo -e "${GREEN}  [+] Tomcat descargado.${NC}"
    else
        hacer_placeholder "${TOMCAT_DIR}/${TC_PKG}" "placeholder-tomcat-${TC_VER}"
    fi
fi

# -- vsftpd para Linux --
VSFTPD_DIR="${FTP_ROOT}/http/Linux/vsftpd"
VSFTPD_PKG="vsftpd-3.0.5-5.el9.x86_64.rpm"
if [ ! -f "${VSFTPD_DIR}/${VSFTPD_PKG}" ]; then
    hacer_placeholder "${VSFTPD_DIR}/${VSFTPD_PKG}" "placeholder-vsftpd-3.0.5"
fi

# ── Permisos finales ──────────────────────────────────────────
chown -R "$FTP_USER":"$FTP_USER" "$FTP_ROOT"
find "$FTP_ROOT" -type d -exec chmod 755 {} \;
find "$FTP_ROOT" -type f -exec chmod 644 {} \;

# ── Mostrar estructura ────────────────────────────────────────
echo ""
echo -e "${CYAN}--- Estructura del repositorio FTP ---${NC}"
find "$FTP_ROOT" -maxdepth 4 | sort | sed "s|${FTP_ROOT}||" | sed 's|[^/]*/|  |g'

echo ""
echo -e "${GREEN}${BOLD}[+] Repositorio listo en: ${FTP_ROOT}${NC}"
echo -e "${BLUE}[*] Acceso: ftp://<ip>/http/Linux/<Servicio>/${NC}"