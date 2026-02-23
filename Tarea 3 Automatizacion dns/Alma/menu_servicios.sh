#!/bin/bash

source ./funciones_servicios.sh

verificar_root

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
    echo "7) Ver Dominios DNS configurados"
    echo "8) Borrar Dominio DNS"
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