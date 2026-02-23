#!/bin/bash

# IMPORTAR TODAS LAS BIBLIOTECAS DE FUNCIONES
source ./funciones_red.sh         
source ./funciones_servicios.sh   

verificar_root

# SUBMENÚS

function menu_ssh() {
    while true; do
        clear
        echo -e "${CYAN}===================================================${NC}"
        echo -e "${YELLOW}${BOLD}           SUBMENÚ DE ADMINISTRACIÓN - SSH         ${NC}"
        echo -e "${CYAN}===================================================${NC}"
        echo -e "  1. Instalar / Reinstalar OpenSSH (Idempotente)"
        echo -e "  2. Configurar IP Estática y Habilitar Acceso Remoto"
        echo -e "  3. Verificar estado del servicio SSH"
        echo -e "  0. Volver al Menú Principal"
        echo -e "${CYAN}===================================================${NC}"
        read -p $'\e[1;32mSelecciona una opción [0-3]: \e[0m' op_ssh

        case $op_ssh in
            1) instalar_ssh_idempotente; read -p $'\n\e[1;34mPresiona Enter...\e[0m' ;;
            2) configurar_ip_estatica && habilitar_acceso_remoto; read -p $'\n\e[1;34mPresiona Enter...\e[0m' ;;
            3) verificar_estado_ssh; read -p $'\n\e[1;34mPresiona Enter...\e[0m' ;;
            0) break ;;
            *) echo -e "${RED}Opción inválida.${NC}"; sleep 1 ;;
        esac
    done
}

function menu_dhcp() {
    while true; do
        clear
        echo -e "${CYAN}===================================================${NC}"
        echo -e "${YELLOW}${BOLD}          SUBMENÚ DE ADMINISTRACIÓN - DHCP         ${NC}"
        echo -e "${CYAN}===================================================${NC}"
        echo -e "  1. Verificar estado de la instalación (DHCP/DNS)"
        echo -e "  2. Instalar Servicios de Red"
        echo -e "  3. Consulta de servicio (Status Active)"
        echo -e "  4. Crear / Configurar Ámbito DHCP"
        echo -e "  5. Monitorear IPs asignadas (Leases)"
        echo -e "  0. Volver al Menú Principal"
        echo -e "${CYAN}===================================================${NC}"
        read -p $'\e[1;32mSelecciona una opción [0-5]: \e[0m' op_dhcp

        case $op_dhcp in
            1) f_verificar_instalacion ;;
            2) f_instalar_servicios ;;
            3) f_consulta_servicio ;;
            4) f_configurar_dhcp ;;
            5) f_monitorear_ips ;;
            0) break ;;
            *) echo -e "${RED}Opción inválida.${NC}"; sleep 1 ;;
        esac
    done
}

function menu_dns() {
    while true; do
        clear
        echo -e "${CYAN}===================================================${NC}"
        echo -e "${YELLOW}${BOLD}           SUBMENÚ DE ADMINISTRACIÓN - DNS         ${NC}"
        echo -e "${CYAN}===================================================${NC}"
        echo -e "  1. Verificar estado de la instalación (DHCP/DNS)"
        echo -e "  2. Instalar Servicios de Red"
        echo -e "  3. Crear nuevo Dominio DNS"
        echo -e "  4. Ver Dominios DNS configurados"
        echo -e "  5. Borrar Dominio DNS"
        echo -e "  0. Volver al Menú Principal"
        echo -e "${CYAN}===================================================${NC}"
        read -p $'\e[1;32mSelecciona una opción [0-5]: \e[0m' op_dns

        case $op_dns in
            1) f_verificar_instalacion ;;
            2) f_instalar_servicios ;;
            3) f_crear_dominio ;;
            4) f_ver_dominios ;;
            5) f_borrar_dominio ;;
            0) break ;;
            *) echo -e "${RED}Opción inválida.${NC}"; sleep 1 ;;
        esac
    done
}

# MENÚ PRINCIPAL

while true; do
    clear
    echo -e "${CYAN}===================================================${NC}"
    echo -e "${GREEN}${BOLD}     SISTEMA CENTRAL DE ADMINISTRACIÓN - ALMALINUX ${NC}"
    echo -e "${CYAN}===================================================${NC}"
    echo -e "  1. Gestión de SSH (Acceso Remoto)"
    echo -e "  2. Gestión de DHCP"
    echo -e "  3. Gestión de DNS"
    echo -e "  0. Salir del Sistema"
    echo -e "${CYAN}===================================================${NC}"
    read -p $'\e[1;32mSelecciona un servicio [0-3]: \e[0m' opcion_principal

    case $opcion_principal in
        1) menu_ssh ;;
        2) menu_dhcp ;;
        3) menu_dns ;;
        0) clear; echo -e "${MAGENTA}Saliendo del sistema central...${NC}"; exit 0 ;;
        *) echo -e "${RED}Opción inválida.${NC}"; sleep 2 ;;
    esac
done