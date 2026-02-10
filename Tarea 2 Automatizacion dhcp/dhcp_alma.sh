#!/bin/bash

# --- CONFIGURACIÓN DE COLORES PARA LA INTERFAZ ---
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# Función para validar IPv4
validar_ip() {
    local ip=$1
    local stat=1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# --- 1. INSTALACIÓN SILENCIOSA ---
clear
echo -e "${CYAN}=========================================================="
echo -e "   AUTOMATIZACIÓN DHCP PROFESIONAL - ALMALINUX"
echo -e "==========================================================${NC}"

echo -n "[*] Verificando infraestructura de red... "
if ! rpm -q dhcp-server &> /dev/null; then
    echo -e "${RED}No instalado.${NC}"
    echo -n "[*] Instalando isc-dhcp-server de forma desatendida... "
    # Instalación sin salida de texto
    dnf install -y dhcp-server &> /dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}LOGRADO${NC}"
    else
        echo -e "${RED}ERROR EN INSTALACIÓN${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}PRESENTE (IDEMPOTENTE)${NC}"
fi

# --- 2. ORQUESTACIÓN DE CONFIGURACIÓN DINÁMICA ---
echo -e "\n${CYAN}>>> Configuración de Parámetros de Ámbito${NC}"

read -p "Nombre del Ámbito (Scope Name): " SCOPE

while true; do
    read -p "Rango Inicial (Ejem: 192.168.100.50): " IP_INI
    validar_ip "$IP_INI" && break
    echo -e "${RED}Formato IP inválido. Intente de nuevo.${NC}"
done

while true; do
    read -p "Rango Final (Ejem: 192.168.100.150): " IP_FIN
    validar_ip "$IP_FIN" && break
    echo -e "${RED}Formato IP inválido. Intente de nuevo.${NC}"
done

read -p "Tiempo de concesión (Lease Time en segundos): " LEASE

while true; do
    read -p "Puerta de Enlace (192.168.100.1): " GW
    validar_ip "$GW" && break
    echo -e "${RED}Formato IP inválido.${NC}"
done

while true; do
    read -p "Servidor DNS (192.168.100.10): " DNS_SRV
    validar_ip "$DNS_SRV" && break
    echo -e "${RED}Formato IP inválido.${NC}"
done

# --- 3. IMPLEMENTACIÓN DE LÓGICA DE CONFIGURACIÓN ---
NET_ID=$(echo $IP_INI | cut -d. -f1-3).0

cat <<EOF > /etc/dhcp/dhcpd.conf
# Configuración Maestra DHCP - $SCOPE
option domain-name-servers $DNS_SRV;
default-lease-time $LEASE;
max-lease-time $((LEASE * 2));
authoritative;

subnet $NET_ID netmask 255.255.255.0 {
  range $IP_INI $IP_FIN;
  option routers $GW;
  option subnet-mask 255.255.255.0;
  option broadcast-address $(echo $NET_ID | sed 's/0$/255/');
}
EOF

# --- 4. VALIDACIÓN DE SINTAXIS Y DESPLIEGUE ---
echo -e "\n[*] Validando integridad del archivo de configuración..."
if dhcpd -t -cf /etc/dhcp/dhcpd.conf &> /dev/null; then
    echo -e "${GREEN}[+] Sintaxis válida.${NC}"

    # Configuración de Firewall
    firewall-cmd --add-service=dhcp --permanent &> /dev/null
    firewall-cmd --reload &> /dev/null

    # Reinicio
    systemctl enable dhcpd &> /dev/null
    systemctl restart dhcpd

    # --- 5. MÓDULO DE MONITOREO Y VALIDACIÓN ---
    echo -e "\n${CYAN}=========================================================="
    echo -e "           MONITOREO Y ESTADO DEL SERVICIO"
    echo -e "==========================================================${NC}"

    STATUS=$(systemctl is-active dhcpd)
    if [ "$STATUS" == "active" ]; then
        echo -e "Estado: ${GREEN}ACTIVO Y FUNCIONANDO${NC}"
    else
        echo -e "Estado: ${RED}INACTIVO - Revise logs con journalctl -xe${NC}"
    fi


    echo -e "\nLista de Concesiones Activas (Leases):"
echo "----------------------------------------------------------"
if [ -f /var/lib/dhcpd/dhcpd.leases ]; then
    awk '/lease / {ip=$2} /hardware ethernet/ {mac=$3} /client-hostname/ {print "IP: " ip " | MAC: " mac " | Equipo: " $2}' /var/lib/dhcpd/dhcpd.leases | sed 's/[";]//g' | uniq
else
    echo "No hay archivo de concesiones aún."
fi


    echo "----------------------------------------------------------"
else
    echo -e "${RED}[!] Error crítico en la sintaxis de dhcpd.conf. Revise los parámetros ingresados.${NC}"
    exit 1
fi