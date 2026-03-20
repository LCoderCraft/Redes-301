#!/bin/bash
# ============================================================
# setup_ftp_repo.sh - Prepara el repositorio FTP con sha256
# Ejecutar en el servidor FTP ANTES de usar el orquestador
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

FTP_ROOT="/srv/ftp/repo"

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Setup Repositorio FTP - Práctica 7      ${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"

# Crear estructura de directorios
for os in Linux Windows; do
    for srv in Apache Nginx Tomcat vsftpd IIS; do
        mkdir -p "${FTP_ROOT}/http/${os}/${srv}"
    done
done
echo -e "${GREEN}[+] Estructura de directorios creada.${NC}"

# ── Descargar paquetes de ejemplo para Linux ──────────────────
echo -e "${BLUE}[*] Descargando instaladores de ejemplo...${NC}"

# Apache para Linux (RPM de AlmaLinux mirror)
APACHE_DIR="${FTP_ROOT}/http/Linux/Apache"
APACHE_PKG="httpd-2.4.62-1.el9.x86_64.rpm"
APACHE_URL="https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/Packages/h/${APACHE_PKG}"

if [ ! -f "${APACHE_DIR}/${APACHE_PKG}" ]; then
    echo -e "${BLUE}[*] Intentando descargar Apache RPM...${NC}"
    if curl -L -f -s --max-time 60 -o "${APACHE_DIR}/${APACHE_PKG}" "$APACHE_URL"; then
        sha256sum "${APACHE_DIR}/${APACHE_PKG}" | awk '{print $1}' > "${APACHE_DIR}/${APACHE_PKG}.sha256"
        echo -e "${GREEN}[+] Apache RPM descargado y hash generado.${NC}"
    else
        echo -e "${YELLOW}[!] No se pudo descargar Apache RPM. Creando placeholder...${NC}"
        echo "placeholder-apache-2.4" > "${APACHE_DIR}/${APACHE_PKG}"
        sha256sum "${APACHE_DIR}/${APACHE_PKG}" | awk '{print $1}' > "${APACHE_DIR}/${APACHE_PKG}.sha256"
    fi
fi

# Nginx para Linux
NGINX_DIR="${FTP_ROOT}/http/Linux/Nginx"
NGINX_PKG="nginx-1.26.2-1.el9.ngx.x86_64.rpm"
NGINX_URL="https://nginx.org/packages/centos/9/x86_64/RPMS/${NGINX_PKG}"

if [ ! -f "${NGINX_DIR}/${NGINX_PKG}" ]; then
    echo -e "${BLUE}[*] Intentando descargar Nginx RPM...${NC}"
    if curl -L -f -s --max-time 60 -o "${NGINX_DIR}/${NGINX_PKG}" "$NGINX_URL"; then
        sha256sum "${NGINX_DIR}/${NGINX_PKG}" | awk '{print $1}' > "${NGINX_DIR}/${NGINX_PKG}.sha256"
        echo -e "${GREEN}[+] Nginx RPM descargado y hash generado.${NC}"
    else
        echo -e "${YELLOW}[!] Creando placeholder Nginx...${NC}"
        echo "placeholder-nginx-1.26" > "${NGINX_DIR}/${NGINX_PKG}"
        sha256sum "${NGINX_DIR}/${NGINX_PKG}" | awk '{print $1}' > "${NGINX_DIR}/${NGINX_PKG}.sha256"
    fi
fi

# Tomcat para Linux
TOMCAT_DIR="${FTP_ROOT}/http/Linux/Tomcat"
TC_VER="10.1.34"
TC_PKG="apache-tomcat-${TC_VER}.tar.gz"
TC_URL="https://downloads.apache.org/tomcat/tomcat-10/v${TC_VER}/bin/${TC_PKG}"

if [ ! -f "${TOMCAT_DIR}/${TC_PKG}" ]; then
    echo -e "${BLUE}[*] Descargando Tomcat ${TC_VER}...${NC}"
    if curl -L -f -s --max-time 120 -o "${TOMCAT_DIR}/${TC_PKG}" "$TC_URL"; then
        sha256sum "${TOMCAT_DIR}/${TC_PKG}" | awk '{print $1}' > "${TOMCAT_DIR}/${TC_PKG}.sha256"
        echo -e "${GREEN}[+] Tomcat descargado y hash generado.${NC}"
    else
        echo -e "${YELLOW}[!] No se pudo descargar Tomcat.${NC}"
    fi
fi

# vsftpd para Linux
VSFTPD_DIR="${FTP_ROOT}/http/Linux/vsftpd"
VSFTPD_PKG="vsftpd-3.0.5-5.el9.x86_64.rpm"
if [ ! -f "${VSFTPD_DIR}/${VSFTPD_PKG}" ]; then
    echo "placeholder-vsftpd-3.0.5" > "${VSFTPD_DIR}/${VSFTPD_PKG}"
    sha256sum "${VSFTPD_DIR}/${VSFTPD_PKG}" | awk '{print $1}' > "${VSFTPD_DIR}/${VSFTPD_PKG}.sha256"
    echo -e "${YELLOW}[!] Placeholder vsftpd creado.${NC}"
fi

# ── Permisos ──────────────────────────────────────────────────
chown -R ftpuser:ftpuser "${FTP_ROOT}" 2>/dev/null || \
    chown -R ftp:ftp "${FTP_ROOT}" 2>/dev/null
find "${FTP_ROOT}" -type d -exec chmod 755 {} \;
find "${FTP_ROOT}" -type f -exec chmod 644 {} \;

# ── Mostrar estructura final ──────────────────────────────────
echo ""
echo -e "${CYAN}── Estructura del repositorio FTP ──${NC}"
find "${FTP_ROOT}" -maxdepth 4 | sort | sed 's|[^/]*/|  |g'

echo ""
echo -e "${GREEN}${BOLD}[+] Repositorio listo en: ${FTP_ROOT}${NC}"
echo -e "${BLUE}[*] Conectar con:  ftp://<ip>${FTP_ROOT#/srv/ftp/repo}${NC}"