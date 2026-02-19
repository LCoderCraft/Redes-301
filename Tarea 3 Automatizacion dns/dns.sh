#!/bin/bash

# --- CONFIGURACIÓN DE COLORES ---
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' 

# --- VALIDACIÓN DE PRIVILEGIOS ---
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Error: Este script modifica archivos del sistema y requiere permisos de administrador.${NC}"
    echo -e "Por favor, ejecútalo usando: ${YELLOW}sudo $0${NC}"
    exit 1
fi

LEASES="/var/lib/dhcpd/dhcpd.leases"
ZONES_FILE="/etc/named.conf"
NAMED_DIR="/var/named"

# --- FUNCIONES PARA IPs ---

ip_to_int() {
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    echo "$(( (a << 24) + (b << 16) + (c << 8) + d ))"
}

int_to_ip() {
    local ui32=$1
    local ip n
    for n in 1 2 3 4; do
        ip=$((ui32 & 0xff))${ip:+.}$ip
        ui32=$((ui32 >> 8))
    done
    echo $ip
}

# --- FUNCIONES DE VALIDACIÓN ---

validar_ip() {
    local ip=$1
    if [[ "$ip" == "localhost" || "$ip" == "127.0.0.0" || "$ip" == "0.0.0.0" ]]; then
        return 1
    fi
    
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        read -r a b c d <<< "$ip"
        if [[ $a -le 255 && $b -le 255 && $c -le 255 && $d -le 255 ]]; then
            return 0
        fi
    fi
    return 1
}

validar_mascara() {
    local ip=$1
    validar_ip "$ip" || return 1
    
    local m=$(ip_to_int "$ip")
    local valid=0
    for i in {1..32}; do
        if [ $m -eq $(( (0xFFFFFFFF << (32 - i)) & 0xFFFFFFFF )) ]; then
            valid=1
            break
        fi
    done
    return $((1 - valid))
}

mascara_a_cidr() {
    local x=$(ip_to_int "$1")
    local c=0
    for i in {31..0}; do
        if [ $(( (x >> i) & 1 )) -eq 1 ]; then c=$((c+1)); else break; fi
    done
    echo $c
}

# --- FUNCIONES DEL MENÚ ---

f_verificar_instalacion() {
    clear
    echo -e "${CYAN}=== VERIFICACIÓN DE INSTALACIÓN ===${NC}"
    
    # Verificar DHCP
    if rpm -q dhcp-server &> /dev/null; then
        echo -e "DHCP: ${GREEN}isc-dhcp-server YA ESTÁ INSTALADO.${NC}"
    else
        echo -e "DHCP: ${RED}isc-dhcp-server NO ESTÁ INSTALADO.${NC}"
    fi

    # Verificar DNS
    if rpm -q bind bind-utils &> /dev/null; then
        echo -e "DNS:  ${GREEN}bind (BIND9) YA ESTÁ INSTALADO.${NC}"
    else
        echo -e "DNS:  ${RED}bind (BIND9) NO ESTÁ INSTALADO.${NC}"
    fi
    echo ""
    read -p "Presione ENTER para continuar..."
}

f_instalar_servicios() {
    clear
    echo -e "${CYAN}=== INSTALACIÓN DE SERVICIOS (DHCP y DNS) ===${NC}"
    
    # 1. Instalar DHCP
    if rpm -q dhcp-server &> /dev/null; then
        echo -e "${YELLOW}[DHCP] El servicio ya se encuentra instalado.${NC}"
    else
        echo -n "[*] Instalando isc-dhcp-server... "
        dnf install -y dhcp-server &> /dev/null && echo -e "${GREEN}ÉXITO${NC}" || echo -e "${RED}ERROR${NC}"
    fi

    # 2. Instalar DNS (BIND9)
    if rpm -q bind bind-utils &> /dev/null; then
        echo -e "${YELLOW}[DNS] El servicio BIND9 ya se encuentra instalado.${NC}"
    else
        echo -n "[*] Instalando bind y bind-utils... "
        if dnf install -y bind bind-utils &> /dev/null; then
            echo -e "${GREEN}ÉXITO${NC}"
            
            # Configuración base de BIND para escuchar en todas las interfaces
            sed -i 's/listen-on port 53 { 127.0.0.1; };/listen-on port 53 { any; };/' /etc/named.conf
            sed -i 's/allow-query     { localhost; };/allow-query     { any; };/' /etc/named.conf
            
            firewall-cmd --add-service=dns --permanent &> /dev/null
            firewall-cmd --reload &> /dev/null
            systemctl enable --now named &> /dev/null
        else
            echo -e "${RED}ERROR${NC}"
        fi
    fi
    
    echo ""
    read -p "Presione ENTER para continuar..."
}

f_consulta_servicio() {
    clear
    echo -e "${CYAN}=== ESTADO DE LOS SERVICIOS ===${NC}"
    
    echo -e "\n${YELLOW}--- DHCP (dhcpd) ---${NC}"
    if systemctl is-active dhcpd &> /dev/null; then
        echo -e "Estado: ${GREEN}ACTIVO Y FUNCIONANDO${NC}"
        systemctl status dhcpd --no-pager | grep -E "Active:|Loaded:"
    else
        echo -e "Estado: ${RED}INACTIVO O CON ERRORES${NC}"
    fi

    echo -e "\n${YELLOW}--- DNS (named) ---${NC}"
    if systemctl is-active named &> /dev/null; then
        echo -e "Estado: ${GREEN}ACTIVO Y FUNCIONANDO${NC}"
        systemctl status named --no-pager | grep -E "Active:|Loaded:"
    else
        echo -e "Estado: ${RED}INACTIVO O CON ERRORES${NC}"
    fi

    echo ""
    read -p "Presione ENTER para continuar..."
}

f_configurar_dhcp() {
    clear
    echo -e "${CYAN}=== CREAR / CONFIGURAR ÁMBITO DHCP ===${NC}"
    
    read -p "Nombre del Ámbito (Scope Name): " SCOPE
    if [[ -z "$SCOPE" ]]; then SCOPE="Ambito_Local"; fi

    while true; do
        read -p "Rango Inicial (Ejem: 10.0.0.2): " IP_INI
        validar_ip "$IP_INI" && break
        echo -e "${RED}IP inválida o restringida.${NC}"
    done

    while true; do
        read -p "Rango Final (Ejem: 10.0.0.50): " IP_FIN
        if validar_ip "$IP_FIN"; then
            INT_INI=$(ip_to_int "$IP_INI")
            INT_FIN=$(ip_to_int "$IP_FIN")
            if [ "$INT_FIN" -gt "$INT_INI" ]; then break; else echo -e "${RED}Error: El Rango Final debe ser mayor al Inicial.${NC}"; fi
        else
            echo -e "${RED}Formato de IP inválido.${NC}"
        fi
    done

    while true; do
        read -p "Máscara de subred (Ejem: 255.0.0.0): " MASCARA
        validar_mascara "$MASCARA" && break
        echo -e "${RED}Máscara de subred inválida.${NC}"
    done

    while true; do
        read -p "Tiempo de concesión (segundos, min 60): " LEASE
        if [[ "$LEASE" =~ ^[0-9]+$ ]] && [ "$LEASE" -ge 60 ]; then break; else echo -e "${RED}Error: Mínimo 60 seg.${NC}"; fi
    done

    while true; do
        read -p "Puerta de Enlace (Enter para dejar vacío): " GW
        if [[ -z "$GW" ]]; then break; fi
        validar_ip "$GW" && break
        echo -e "${RED}Formato de IP inválido.${NC}"
    done

    while true; do
        read -p "Servidor DNS (Enter para usar $IP_INI): " DNS_SRV
        if [[ -z "$DNS_SRV" ]]; then DNS_SRV="$IP_INI"; break; fi
        validar_ip "$DNS_SRV" && break
        echo -e "${RED}Formato de IP inválido.${NC}"
    done

    # Cálculos
    INT_MASK=$(ip_to_int "$MASCARA")
    INT_NET_ID=$(( INT_INI & INT_MASK ))
    NET_ID=$(int_to_ip $INT_NET_ID)
    INT_BCAST=$(( INT_NET_ID | (0xFFFFFFFF ^ INT_MASK) ))
    BCAST=$(int_to_ip $INT_BCAST)
    
    SERVER_IP=$IP_INI
    DHCP_START_IP=$(int_to_ip $(( INT_INI + 1 )))
    INTERFAZ="enp0s8"

    echo -e "\n${YELLOW}[*] Resumen Lógico (${SCOPE}):${NC}"
    echo "- Interfaz objetivo: $INTERFAZ"
    echo "- La IP $SERVER_IP será asignada al servidor de forma fija."
    echo "- Los clientes recibirán IPs desde $DHCP_START_IP hasta $IP_FIN."
    echo "- ID Red: $NET_ID | Broadcast: $BCAST | DNS Asignado: $DNS_SRV"

    CIDR=$(mascara_a_cidr "$MASCARA")
    echo "[*] Configurando IP fija ($SERVER_IP/$CIDR) en la interfaz $INTERFAZ..."
    
    if ! nmcli -t -f NAME connection show | grep -wq "^$INTERFAZ$"; then
        nmcli connection add type ethernet ifname "$INTERFAZ" con-name "$INTERFAZ" &> /dev/null
    fi
    nmcli con mod "$INTERFAZ" ipv4.addresses "$SERVER_IP/$CIDR" ipv4.method manual &> /dev/null
    nmcli con up "$INTERFAZ" &> /dev/null

    echo "[*] Generando /etc/dhcp/dhcpd.conf..."
    OPT_GW=""; [ -n "$GW" ] && OPT_GW="option routers $GW;"
    OPT_DNS=""; [ -n "$DNS_SRV" ] && OPT_DNS="option domain-name-servers $DNS_SRV;"

    cat <<EOF > /etc/dhcp/dhcpd.conf
default-lease-time $LEASE;
max-lease-time $((LEASE * 2));
authoritative;

$OPT_DNS

subnet $NET_ID netmask $MASCARA {
  range $DHCP_START_IP $IP_FIN;
  $OPT_GW
  option subnet-mask $MASCARA;
  option broadcast-address $BCAST;
}
EOF

    echo "[*] Validando configuración DHCP..."
    if dhcpd -t -cf /etc/dhcp/dhcpd.conf &> /dev/null; then
        echo -e "${GREEN}[+] Sintaxis válida.${NC}"
        firewall-cmd --add-service=dhcp --permanent &> /dev/null
        firewall-cmd --reload &> /dev/null
        systemctl enable dhcpd &> /dev/null
        systemctl restart dhcpd
        if systemctl is-active dhcpd &> /dev/null; then echo -e "${GREEN}[+] DHCP CONFIGURADO Y ACTIVO.${NC}"; else echo -e "${RED}[!] Error al arrancar DHCP.${NC}"; fi
    else
        echo -e "${RED}[!] Error en sintaxis de dhcpd.conf.${NC}"
    fi
    echo ""
    read -p "Presione ENTER para continuar..."
}

# --- FUNCIONES DE GESTIÓN DNS ---

# --- FUNCIÓN AUXILIAR PARA LEER DOMINIOS ---
mostrar_lista_dominios() {
    echo -e "DOMINIO              IP ASIGNADA"
    echo "----------------------------------------"
    
    # Extraer nombres de dominios ignorando los de sistema (localhost, etc)
    local dominios=$(grep '^zone "' /etc/named.conf 2>/dev/null | awk -F'"' '{print $2}')
    local hay_dominios=0
    
    for d in $dominios; do
        local zone_file="/var/named/$d.zone"
        if [ -f "$zone_file" ]; then
            # Extraer la IP del registro A principal
            local ip=$(grep -E "^@\s+IN\s+A" "$zone_file" | awk '{print $4}')
            printf "%-20s %s\n" "$d" "${ip}"
            hay_dominios=1
        fi
    done
    
    if [ $hay_dominios -eq 0 ]; then
        echo -e "${YELLOW}No hay dominios creados aún.${NC}"
    fi
    echo "----------------------------------------"
}

# --- FUNCIÓN PARA EL MENÚ (VER DOMINIOS) ---
f_ver_dominios() {
    clear
    echo -e "${CYAN}=== DOMINIOS DNS CONFIGURADOS ===${NC}"
    mostrar_lista_dominios
    echo ""
    read -p "Presione ENTER para continuar..."
}

f_crear_dominio() {
    clear
    echo -e "${CYAN}=== CREAR NUEVO DOMINIO DNS ===${NC}"
    read -p "Introduce el nombre del dominio (ej. reprobados.com): " DOMINIO
    read -p "Introduce la IP a la que apuntará (ej. 10.0.0.2): " IP_TARGET

    ZONE_FILE="$NAMED_DIR/$DOMINIO.zone"

    if grep -q "zone \"$DOMINIO\"" "$ZONES_FILE"; then
        echo -e "${YELLOW}El dominio $DOMINIO ya existe en la configuración.${NC}"
        read -p "Presione ENTER para continuar..."
        return
    fi

    echo "[*] Creando archivo de zona $ZONE_FILE..."
    cat <<EOF > "$ZONE_FILE"
\$TTL 86400
@   IN  SOA     ns1.$DOMINIO. root.$DOMINIO. ( 2026021801 3600 1800 604800 86400 )
@   IN  NS      ns1.$DOMINIO.
ns1 IN  A       $IP_TARGET
@   IN  A       $IP_TARGET
www IN  CNAME   $DOMINIO.
EOF

    chown root:named "$ZONE_FILE"
    chmod 640 "$ZONE_FILE"

    echo "[*] Agregando zona a $ZONES_FILE..."
    cat <<EOF >> "$ZONES_FILE"

zone "$DOMINIO" IN {
    type master;
    file "$ZONE_FILE";
    allow-update { none; };
};
EOF

    named-checkconf
    if [ $? -eq 0 ]; then
        systemctl restart named
        echo -e "${GREEN}[+] Dominio $DOMINIO creado con éxito apuntando a $IP_TARGET.${NC}"
    else
        echo -e "${RED}[!] Error de sintaxis en BIND.${NC}"
    fi
    echo ""
    read -p "Presione ENTER para continuar..."
}

f_borrar_dominio() {
    clear
    echo -e "${CYAN}=== BORRAR DOMINIO DNS ===${NC}"
    mostrar_lista_dominios
    echo ""
    read -p "Introduce el nombre del dominio a borrar (o presiona ENTER para cancelar): " DOMINIO
    
    if [[ -z "$DOMINIO" ]]; then return; fi

    ZONE_FILE="$NAMED_DIR/$DOMINIO.zone"

    if [ -f "$ZONE_FILE" ]; then
        rm -f "$ZONE_FILE"
        echo "[*] Archivo de zona $ZONE_FILE eliminado."
    fi

    # EL ARREGLO ESTÁ AQUÍ: Se agregó ^}; para borrar el bloque exacto
    sed -i "/zone \"$DOMINIO\" IN {/,/^};/d" "$ZONES_FILE"
    systemctl restart named
    
    echo -e "${GREEN}[+] Dominio $DOMINIO borrado y servicio reiniciado.${NC}"
    echo ""
    read -p "Presione ENTER para continuar..."
}

f_monitorear_ips() {
    clear
    echo -e "${CYAN}=== IPs ASIGNADAS ACTUALMENTE ===${NC}"
    echo "IP ASIGNADA          EQUIPO"
    echo "----------------------------------------"
    if [ -f "$LEASES" ]; then
        awk '/^lease / { ip=$2 } /client-hostname/ { gsub(/[";]/,"",$2); host=$2 } /binding state active/ { if (!(host in seen)) { printf "%-20s %s\n", ip, host; seen[host]=1 } }' "$LEASES"
    else
        echo -e "${YELLOW}El archivo de concesiones aún no existe o está vacío.${NC}"
    fi
    echo "----------------------------------------"
    read -p "Presione ENTER para continuar..."
}

# --- BUCLE PRINCIPAL DEL MENÚ ---
# --- BUCLE PRINCIPAL DEL MENÚ ---
while true; do
    clear
    echo -e "${CYAN}==========================================${NC}"
    echo -e " ${GREEN}GESTOR AUTOMATIZADO DNS Y DHCP - ALMALINUX${NC}"
    echo -e "${CYAN}==========================================${NC}"
    echo "1) Verificar instalación de paquetes"
    echo "2) Instalar Servicios (DNS y DHCP)"
    echo "3) Consulta de servicio (Status Active)"
    echo "4) Crear / Configurar Ámbito DHCP"
    echo "5) Monitorear IPs asignadas (DHCP)"
    echo "6) Crear nuevo Dominio DNS"
    echo "7) Ver Dominios DNS configurados"  # <--- NUEVA OPCIÓN
    echo "8) Borrar Dominio DNS"             # <--- RECORRIDO
    echo "9) Salir"
    echo -e "${CYAN}==========================================${NC}"
    read -p "Seleccione una opción: " op

    case $op in
        1) f_verificar_instalacion ;;
        2) f_instalar_servicios ;;
        3) f_consulta_servicio ;;
        4) f_configurar_dhcp ;;
        5) f_monitorear_ips ;;
        6) f_crear_dominio ;;
        7) f_ver_dominios ;;
        8) f_borrar_dominio ;;
        9) clear; echo "Saliendo del sistema..."; exit 0 ;;
        *) echo -e "${RED}Opción inválida.${NC}"; sleep 1 ;;
    esac
done