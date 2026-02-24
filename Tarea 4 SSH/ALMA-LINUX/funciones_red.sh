#!/bin/bash
# funciones_red.sh

IP_ASIGNADA=""

# COLORES
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[1;35m'
NC='\033[0m'
BOLD='\033[1m'

# FUNCIONES

function verificar_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}${BOLD}Error: Debes ejecutar este script como root.${NC}"
        exit 1
    fi
}

function instalar_ssh_idempotente() {
    echo -e "${CYAN}--- Instalación de OpenSSH Server ---${NC}"
    if rpm -q "openssh-server" &> /dev/null; then
        echo -e "${YELLOW}[!] OpenSSH Server ya está instalado en el sistema.${NC}"
        read -p $'\e[1;33m¿Deseas reinstalarlo? (s/n): \e[0m' respuesta
        if [[ "$respuesta" =~ ^[sS]$ ]]; then
            echo -e "${BLUE}[*] Reinstalando OpenSSH Server...${NC}"
            dnf reinstall -y openssh-server &> /dev/null
            echo -e "${GREEN}${BOLD}[+] Reinstalación completada.${NC}"
        else
            echo -e "${BLUE}[*] Omitiendo instalación.${NC}"
        fi
    else
        echo -e "${BLUE}[*] Instalando OpenSSH Server...${NC}"
        dnf install -y openssh-server &> /dev/null
        echo -e "${GREEN}${BOLD}[+] Instalación completada.${NC}"
    fi
}

function configurar_ip_estatica() {
    echo -e "${CYAN}--- Configuración de IP Estática (Administración/SSH) ---${NC}"
    
    echo -e "${BLUE}Interfaces de red activas:${NC}"
    nmcli -t -f NAME,DEVICE connection show --active | awk -F: '{print "- " $1 " (Dispositivo: " $2 ")"}'
    
    echo ""
    read -p $'\e[1;33mEscribe el nombre de la interfaz para SSH (ej. enp0s3): \e[0m' conn_name
    
    if ! nmcli -t -f NAME connection show | grep -wq "^$conn_name$"; then
        echo -e "${RED}[!] La conexión '$conn_name' no existe o no es válida.${NC}"
        return 1
    fi

    echo -e "${BLUE}Configurando la interfaz: ${BOLD}$conn_name${NC}"
    read -p $'\e[1;33mIngresa la IP con máscara (ej. 192.168.1.10/24): \e[0m' ip_fija
    
    if [ -z "$ip_fija" ]; then
        echo -e "${RED}[!] La IP es obligatoria. Operación cancelada.${NC}"
        return 1
    fi

    IP_ASIGNADA=$(echo "$ip_fija" | cut -d'/' -f1)

    read -p $'\e[1;33mIngresa la Puerta de Enlace [Enter para dejar vacío]: \e[0m' gateway
    read -p $'\e[1;33mIngresa el servidor DNS [Enter para dejar vacío]: \e[0m' dns

    echo -e "${BLUE}[*] Aplicando configuración de red a $conn_name...${NC}"
    nmcli con mod "$conn_name" ipv4.addresses "$ip_fija"
    nmcli con mod "$conn_name" ipv4.method manual

    if [ -n "$gateway" ]; then
        nmcli con mod "$conn_name" ipv4.gateway "$gateway"
    else
        nmcli con mod "$conn_name" ipv4.gateway "" 
    fi

    if [ -n "$dns" ]; then
        nmcli con mod "$conn_name" ipv4.dns "$dns"
    else
        nmcli con mod "$conn_name" ipv4.dns "" 
    fi

    nmcli con up "$conn_name" &> /dev/null
    echo -e "${GREEN}${BOLD}[+] IP configurada correctamente en $conn_name.${NC}"
}

function habilitar_acceso_remoto() {
    echo -e "${CYAN}--- Habilitando Acceso Remoto SSH ---${NC}"
    
    if ! rpm -q "openssh-server" &> /dev/null; then
        echo -e "${RED}[-] Error: OpenSSH Server NO está instalado.${NC}"
        echo -e "${RED}[-] Por favor, instálalo primero usando la Opción 1 del menú.${NC}"
        return 1
    fi

    echo -e "${BLUE}[*] Configurando el servicio para iniciar en el boot...${NC}"
    systemctl enable sshd --now &> /dev/null
    
    echo -e "${BLUE}[*] Configurando Firewall (Puerto 22)...${NC}"
    firewall-cmd --permanent --add-service=ssh &> /dev/null
    firewall-cmd --reload &> /dev/null

    echo -e "${MAGENTA}==================================================${NC}"
    echo -e "${GREEN}${BOLD}[HITO CRÍTICO ALCANZADO]${NC}"
    echo -e "${GREEN}Ya puedes abandonar esta consola física.${NC}"
    echo -e "${GREEN}Conéctate desde tu cliente: ${BOLD}ssh root@${IP_ASIGNADA}${NC}"
    echo -e "${MAGENTA}==================================================${NC}"
}

function verificar_estado_ssh() {
    echo -e "${CYAN}--- Estado del Servicio SSH ---${NC}"
    if rpm -q "openssh-server" &> /dev/null; then
        if systemctl is-active --quiet sshd; then
            echo -e "${GREEN}[+] Servicio SSH: INSTALADO y ACTIVO (Corriendo).${NC}"
        else
            echo -e "${YELLOW}[-] Servicio SSH: Instalado pero INACTIVO.${NC}"
        fi
        
        if firewall-cmd --list-services | grep -q "ssh"; then
            echo -e "${GREEN}[+] Firewall: Puerto 22 (SSH) PERMITIDO.${NC}"
        else
            echo -e "${RED}[-] Firewall: Puerto 22 (SSH) NO permitido.${NC}"
        fi
    else
        echo -e "${RED}[-] OpenSSH Server: NO INSTALADO.${NC}"
    fi
    echo -e "${CYAN}-------------------------------${NC}"
}