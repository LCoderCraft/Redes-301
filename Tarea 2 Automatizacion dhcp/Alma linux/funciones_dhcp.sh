#!/bin/bash
# funciones_dhcp.sh

# --- CONFIGURACIÓN DE COLORES ---
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' 

LEASES="/var/lib/dhcpd/dhcpd.leases"

# --- VALIDACIÓN DE PRIVILEGIOS ---
function verificar_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] Error: Este script modifica archivos del sistema y requiere permisos de administrador.${NC}"
        echo -e "Por favor, ejecútalo usando: ${YELLOW}sudo ./menu_dhcp.sh${NC}"
        exit 1
    fi
}

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
    if rpm -q dhcp-server &> /dev/null; then
        echo -e "Estado: ${GREEN}isc-dhcp-server YA ESTÁ INSTALADO.${NC}"
    else
        echo -e "Estado: ${RED}isc-dhcp-server NO ESTÁ INSTALADO.${NC}"
    fi
    echo ""
    read -p "Presione ENTER para continuar..."
}

f_instalar_dhcp() {
    clear
    echo -e "${CYAN}=== INSTALACIÓN DE DHCP ===${NC}"
    if rpm -q dhcp-server &> /dev/null; then
        echo -e "${YELLOW}El servicio DHCP ya se encuentra instalado en el sistema.${NC}"
        read -p "¿Desea REINSTALAR (sobreescribir binarios)? (s/n): " resp
        if [[ "$resp" == "s" || "$resp" == "S" ]]; then
            echo -n "[*] Reinstalando isc-dhcp-server... "
            dnf reinstall -y dhcp-server &> /dev/null && echo -e "${GREEN}ÉXITO${NC}" || echo -e "${RED}ERROR${NC}"
        else
            echo "Operación cancelada."
        fi
    else
        echo -n "[*] Instalando isc-dhcp-server de forma desatendida... "
        dnf install -y dhcp-server &> /dev/null && echo -e "${GREEN}ÉXITO${NC}" || echo -e "${RED}ERROR${NC}"
    fi
    echo ""
    read -p "Presione ENTER para continuar..."
}

f_consulta_servicio() {
    clear
    echo -e "${CYAN}=== ESTADO DEL SERVICIO DHCP ===${NC}"
    if systemctl is-active dhcpd &> /dev/null; then
        echo -e "El servicio está: ${GREEN}ACTIVO Y FUNCIONANDO${NC}"
        systemctl status dhcpd --no-pager | head -n 5
    else
        echo -e "El servicio está: ${RED}INACTIVO O CON ERRORES${NC}"
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
        read -p "Rango Inicial (Ejem: 192.168.100.1): " IP_INI
        validar_ip "$IP_INI" && break
        echo -e "${RED}IP inválida o restringida (0.0.0.0, 127.0.0.0, localhost).${NC}"
    done

    while true; do
        read -p "Rango Final (Ejem: 192.168.100.50): " IP_FIN
        if validar_ip "$IP_FIN"; then
            INT_INI=$(ip_to_int "$IP_INI")
            INT_FIN=$(ip_to_int "$IP_FIN")
            if [ "$INT_FIN" -gt "$INT_INI" ]; then
                break
            else
                echo -e "${RED}Error: El Rango Final ($IP_FIN) debe ser mayor al Rango Inicial ($IP_INI).${NC}"
            fi
        else
            echo -e "${RED}Formato de IP inválido.${NC}"
        fi
    done

    while true; do
        read -p "Máscara de subred (Ejem: 255.255.255.0): " MASCARA
        validar_mascara "$MASCARA" && break
        echo -e "${RED}Máscara de subred inválida.${NC}"
    done

    while true; do
        read -p "Tiempo de concesión (segundos, min 60): " LEASE
        if [[ "$LEASE" =~ ^[0-9]+$ ]] && [ "$LEASE" -ge 60 ]; then
            break
        else
            echo -e "${RED}Error: Debe ser un número entero mayor o igual a 60.${NC}"
        fi
    done

    while true; do
        read -p "Puerta de Enlace (Enter para dejar vacío): " GW
        if [[ -z "$GW" ]]; then break; fi
        validar_ip "$GW" && break
        echo -e "${RED}Formato de IP inválido.${NC}"
    done

    while true; do
        read -p "Servidor DNS (Enter para dejar vacío): " DNS_SRV
        if [[ -z "$DNS_SRV" ]]; then break; fi
        validar_ip "$DNS_SRV" && break
        echo -e "${RED}Formato de IP inválido.${NC}"
    done

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
    echo "- ID Red: $NET_ID | Broadcast: $BCAST"

    CIDR=$(mascara_a_cidr "$MASCARA")
    echo "[*] Configurando IP fija ($SERVER_IP/$CIDR) en la interfaz $INTERFAZ..."
    nmcli con mod "$INTERFAZ" ipv4.addresses "$SERVER_IP/$CIDR" ipv4.method manual &> /dev/null
    nmcli con up "$INTERFAZ" &> /dev/null

    echo "[*] Generando /etc/dhcp/dhcpd.conf..."
    
    OPT_GW=""
    [ -n "$GW" ] && OPT_GW="option routers $GW;"
    
    OPT_DNS=""
    [ -n "$DNS_SRV" ] && OPT_DNS="option domain-name-servers $DNS_SRV;"

    cat <<EOF > /etc/dhcp/dhcpd.conf
# Configuración Maestra DHCP - Ámbito: $SCOPE
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
        
        echo "[*] Configurando Firewall y Servicios..."
        firewall-cmd --add-service=dhcp --permanent &> /dev/null
        firewall-cmd --reload &> /dev/null
        
        systemctl enable dhcpd &> /dev/null
        systemctl restart dhcpd
        
        if systemctl is-active dhcpd &> /dev/null; then
            echo -e "${GREEN}[+] SERVICIO DHCP CONFIGURADO Y ACTIVO.${NC}"
        else
            echo -e "${RED}[!] Error al arrancar el servicio DHCP. Revisa 'journalctl -xe'.${NC}"
        fi
    else
        echo -e "${RED}[!] Error en la sintaxis de dhcpd.conf.${NC}"
    fi

    echo ""
    read -p "Presione ENTER para continuar..."
}

f_monitorear_ips() {
    clear
    echo -e "${CYAN}=== IPs ASIGNADAS ACTUALMENTE ===${NC}"
    echo "IP ASIGNADA          EQUIPO"
    echo "----------------------------------------"
    
    if [ -f "$LEASES" ]; then
        awk '
        /^lease / { ip=$2 }
        /client-hostname/ {
            gsub(/[";]/,"",$2)
            host=$2
        }
        /binding state active/ {
            if (!(host in seen)) {
                printf "%-20s %s\n", ip, host
                seen[host]=1
            }
        }' "$LEASES"
    else
        echo -e "${YELLOW}El archivo de concesiones aún no existe o está vacío.${NC}"
    fi
    
    echo "----------------------------------------"
    read -p "Presione ENTER para continuar..."
}