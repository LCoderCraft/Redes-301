#!/bin/bash
# ============================================================
# http.sh - Orquestador Híbrido y Cliente FTP dinámico
# ============================================================
source ./config.sh

# ── FUNCIONES DE SSL / PKI ────────────────────────────────────
function Generar_SSL() {
    if [ ! -f "$CFG_SSL_CRT" ]; then
        echo -e "  Generando certificado PKI autofirmado para $CFG_DOMAIN..."
        mkdir -p "$CFG_SSL_DIR"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$CFG_SSL_KEY" -out "$CFG_SSL_CRT" \
            -subj "/C=MX/ST=Sinaloa/L=Culiacan/O=UAS/CN=$CFG_DOMAIN" 2>/dev/null
        
        # Generar PKCS12 para Tomcat
        openssl pkcs12 -export -in "$CFG_SSL_CRT" -inkey "$CFG_SSL_KEY" \
            -out "$CFG_SSL_P12" -name tomcat -password pass:"$CFG_SSL_PASS" 2>/dev/null
        echo -e "\e[32m  [OK] Certificados generados en $CFG_SSL_DIR\e[0m"
    fi
}

# ── NAVEGACIÓN FTP DINÁMICA ───────────────────────────────────
function Descargar_FTP() {
    local SERVICIO=$1
    mkdir -p "$CFG_DOWNLOAD_DIR"
    
    read -p "  IP del servidor FTP (Ej. 192.168.x.x): " FTP_IP
    read -p "  Usuario FTP: " FTP_USER
    read -s -p "  Contraseña: " FTP_PASS; echo

    local RUTA_REMOTA="ftp://$FTP_IP/http/Linux/$SERVICIO/"
    echo -e "\n  Navegando en: $RUTA_REMOTA"
    
    # Listar archivos omitiendo los .sha256 para mostrar solo binarios
    ARCHIVOS=$(curl -s -u "$FTP_USER:$FTP_PASS" --ftp-ssl -k "$RUTA_REMOTA" | awk '{print $9}' | grep -v '\.sha256$')
    
    if [ -z "$ARCHIVOS" ]; then
        echo -e "\e[31m  [ERROR] No hay archivos en el repositorio para $SERVICIO.\e[0m"
        return 1
    fi

    local i=1
    declare -A MAPA
    for arch in $ARCHIVOS; do
        echo "    $i) $arch"
        MAPA[$i]=$arch
        ((i++))
    done

    read -p "  Selecciona el paquete [1-$(($i-1))]: " SEL
    local ARCHIVO_ELEGIDO=${MAPA[$SEL]}
    local DESTINO="$CFG_DOWNLOAD_DIR/$ARCHIVO_ELEGIDO"

    echo "  Descargando $ARCHIVO_ELEGIDO..."
    curl -u "$FTP_USER:$FTP_PASS" --ftp-ssl -k "$RUTA_REMOTA$ARCHIVO_ELEGIDO" -o "$DESTINO" -s
    echo "  Descargando firma Hash (.sha256)..."
    curl -u "$FTP_USER:$FTP_PASS" --ftp-ssl -k "$RUTA_REMOTA$ARCHIVO_ELEGIDO.sha256" -o "$DESTINO.sha256" -s

    # VALIDACIÓN DE INTEGRIDAD
    if [ -f "$DESTINO.sha256" ]; then
        local HASH_ESPERADO=$(cat "$DESTINO.sha256" | awk '{print $1}')
        local HASH_CALCULADO=$(sha256sum "$DESTINO" | awk '{print $1}')
        
        if [ "$HASH_ESPERADO" == "$HASH_CALCULADO" ]; then
            echo -e "\e[32m  [OK] Integridad verificada (SHA256 coincide).\e[0m"
        else
            echo -e "\e[31m  [ERROR] Archivo corrupto. El hash no coincide.\e[0m"
            rm -f "$DESTINO"
            return 1
        fi
    fi
    echo "$DESTINO"
}

# ── LÓGICA DE INSTALACIÓN (APACHE, NGINX, TOMCAT) ─────────────
function Instalar_Servicio() {
    local SERVICIO=$1
    read -p "  Puerto HTTP [80]: " PUERTO_HTTP
    PUERTO_HTTP=${PUERTO_HTTP:-80}
    
    read -p "¿Desea activar SSL en este servicio? [S/N]: " RESP_SSL
    if [[ "$RESP_SSL" =~ ^[Ss]$ ]]; then
        read -p "  Puerto HTTPS [443]: " PUERTO_HTTPS
        PUERTO_HTTPS=${PUERTO_HTTPS:-443}
        Generar_SSL
    fi

    echo -e "\n  Origen de instalación:"
    echo "    1) Repositorio FTP privado"
    echo "    2) Descarga web / Gestor DNF"
    read -p "  Elige [1/2]: " ORIGEN

    if [ "$ORIGEN" == "1" ]; then
        local BINARIO=$(Descargar_FTP "$SERVICIO")
        if [ -z "$BINARIO" ]; then return; fi
        # Instalar localmente
        if [[ "$BINARIO" == *.rpm ]]; then
            dnf localinstall "$BINARIO" -y > /dev/null
        elif [[ "$BINARIO" == *.tar.gz ]]; then
            tar -xzf "$BINARIO" -C /opt/
        fi
    else
        echo "  Instalando $SERVICIO desde repositorios oficiales..."
        case $SERVICIO in
            "Apache") dnf install httpd mod_ssl -y > /dev/null ;;
            "Nginx")  dnf install nginx --allowerasing -y > /dev/null ;;
            "Tomcat") dnf install java-11-openjdk tomcat tomcat-webapps -y > /dev/null ;;
        esac
    fi

    # Configuración de Puertos y Redirección (HSTS)
    Configurar_Redireccion "$SERVICIO" "$PUERTO_HTTP" "$PUERTO_HTTPS" "$RESP_SSL"

    # Firewall: Abrimos puertos y silenciamos la salida para evitar el mensaje rojo "ALREADY_ENABLED"
    firewall-cmd --add-port=${PUERTO_HTTP}/tcp --permanent &> /dev/null
    if [[ "$RESP_SSL" =~ ^[Ss]$ ]]; then
        firewall-cmd --add-port=${PUERTO_HTTPS}/tcp --permanent &> /dev/null
    fi
    firewall-cmd --reload &> /dev/null

    # Resumen Automatizado
    echo -e "\n============================================="
    echo -e "\e[32m RESUMEN DE INSTALACIÓN: $SERVICIO\e[0m"
    echo -e "  Dominio: $CFG_DOMAIN"
    echo -e "  Puerto HTTP: $PUERTO_HTTP"
    if [[ "$RESP_SSL" =~ ^[Ss]$ ]]; then
        echo -e "  Puerto HTTPS: $PUERTO_HTTPS (SSL Activado)"
        echo -e "  Redirección Forzada (HSTS): Activa"
    fi
    echo -e "=============================================\n"
}

function Configurar_Redireccion() {
    local SERVICIO=$1
    local P_HTTP=$2
    local P_HTTPS=$3
    local USA_SSL=$4

    case $SERVICIO in
        "Apache")
            cat <<EOF > /etc/httpd/conf.d/$CFG_DOMAIN.conf
Listen $P_HTTP
<VirtualHost *:$P_HTTP>
    ServerName $CFG_DOMAIN
    DocumentRoot /var/www/html
EOF
            if [[ "$USA_SSL" =~ ^[Ss]$ ]]; then
                cat <<EOF >> /etc/httpd/conf.d/$CFG_DOMAIN.conf
    Redirect permanent / https://$CFG_DOMAIN:$P_HTTPS/
</VirtualHost>

Listen $P_HTTPS
<VirtualHost *:$P_HTTPS>
    ServerName $CFG_DOMAIN
    DocumentRoot /var/www/html
    SSLEngine on
    SSLCertificateFile $CFG_SSL_CRT
    SSLCertificateKeyFile $CFG_SSL_KEY
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>
EOF
            else
                echo "</VirtualHost>" >> /etc/httpd/conf.d/$CFG_DOMAIN.conf
            fi
            systemctl enable --now httpd &> /dev/null
            systemctl restart httpd
            ;;

        "Nginx")
            local CONF="/etc/nginx/conf.d/$CFG_DOMAIN.conf"
            cat <<EOF > $CONF
server {
    listen $P_HTTP;
    server_name $CFG_DOMAIN;
    root /usr/share/nginx/html;
EOF
            if [[ "$USA_SSL" =~ ^[Ss]$ ]]; then
                cat <<EOF >> $CONF
    return 301 https://\$host:$P_HTTPS\$request_uri;
}

server {
    listen $P_HTTPS ssl;
    server_name $CFG_DOMAIN;
    root /usr/share/nginx/html;
    ssl_certificate $CFG_SSL_CRT;
    ssl_certificate_key $CFG_SSL_KEY;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
EOF
            else
                echo "}" >> $CONF
            fi
            systemctl enable --now nginx &> /dev/null
            systemctl restart nginx
            ;;

        "Tomcat")
            local XML="/etc/tomcat/server.xml"
            if [[ "$USA_SSL" =~ ^[Ss]$ ]]; then
                sed -i "s/port=\"8080\"/port=\"$P_HTTP\" redirectPort=\"$P_HTTPS\"/g" $XML
                # Borramos conector SSL viejo si existe para no duplicarlo al reinstalar
                sed -i '/<Connector port=".*" protocol=".*Http11NioProtocol"/,/clientAuth="false" sslProtocol="TLS" \/>/d' $XML
                # Insertar conector SSL
                sed -i "/<\/Service>/i \
    <Connector port=\"$P_HTTPS\" protocol=\"org.apache.coyote.http11.Http11NioProtocol\" \
               maxThreads=\"150\" SSLEnabled=\"true\" scheme=\"https\" secure=\"true\" \
               keystoreFile=\"$CFG_SSL_P12\" keystorePass=\"$CFG_SSL_PASS\" keystoreType=\"PKCS12\" \
               clientAuth=\"false\" sslProtocol=\"TLS\" />" $XML
            else
                sed -i "s/port=\"8080\"/port=\"$P_HTTP\"/g" $XML
            fi
            systemctl enable --now tomcat &> /dev/null
            systemctl restart tomcat
            ;;
    esac
}