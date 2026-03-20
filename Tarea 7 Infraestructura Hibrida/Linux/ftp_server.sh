#!/bin/bash
# ============================================================
# ftp_server.sh - Configura vsftpd como repositorio seguro
# ============================================================
source ./config.sh

function Instalar_VSFTPD() {
    echo -e "\n[1/3] Instalando vsftpd y generando certificados..."
    dnf install vsftpd openssl -y > /dev/null

    # Certificado para vsftpd
    mkdir -p /etc/ssl/private
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/vsftpd.pem \
        -out /etc/ssl/private/vsftpd.pem \
        -subj "/C=MX/ST=Sinaloa/L=Culiacan/O=UAS/CN=$CFG_DOMAIN" 2>/dev/null

    echo -e "[2/3] Configurando vsftpd.conf con cifrado SSL/TLS..."
    cat <<EOF > /etc/vsftpd/vsftpd.conf
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
xferlog_enable=YES
connect_from_port_20=YES
xferlog_std_format=YES
listen=NO
listen_ipv6=YES
pam_service_name=vsftpd
userlist_enable=YES
tcp_wrappers=YES
# Configuracion SSL/TLS (Obligatoria)
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
rsa_cert_file=/etc/ssl/private/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.pem
local_root=/srv/ftp/repo
EOF

    systemctl restart vsftpd
    systemctl enable vsftpd

    # Abrir Firewall (Silenciando warnings si ya está abierto)
    firewall-cmd --add-service=ftp --permanent &> /dev/null
    firewall-cmd --reload &> /dev/null
    
    echo -e "[3/3] Creando usuario 'repo' y estructura..."
    if ! id "repo" &>/dev/null; then
        useradd -d /srv/ftp/repo -s /sbin/nologin repo
        echo "repo:practica7" | chpasswd
    fi
    
    mkdir -p "$CFG_FTP_REPO/http/Linux/"{Apache,Nginx,Tomcat}
    chown -R repo:repo "$CFG_FTP_REPO"
    chmod -R 755 "$CFG_FTP_REPO"

    echo -e "\e[32m[OK] Servidor FTPS activo. Usuario: repo | Pass: practica7\e[0m"
}

Instalar_VSFTPD