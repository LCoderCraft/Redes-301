#!/bin/bash
source ./funciones_dhcp.sh

verificar_root

while true; do
    clear
    echo -e "${CYAN}==========================================${NC}"
    echo -e " ${GREEN}SISTEMA DE ADMINISTRACIÓN DHCP - ALMALINUX${NC}"
    echo -e "${CYAN}==========================================${NC}"
    echo "1) Verificar instalación"
    echo "2) Instalar DHCP (o Reinstalar)"
    echo "3) Consulta de servicio (Status)"
    echo "4) Crear / Configurar Ámbito DHCP"
    echo "5) Monitorear IPs asignadas"
    echo "6) Salir"
    echo -e "${CYAN}==========================================${NC}"
    read -p "Seleccione una opción: " op

    case $op in
        1) f_verificar_instalacion ;;
        2) f_instalar_dhcp ;;
        3) f_consulta_servicio ;;
        4) f_configurar_dhcp ;;
        5) f_monitorear_ips ;;
        6) 
            clear
            echo "Saliendo del sistema..."
            exit 0 
            ;;
        *)
            echo -e "${RED}Opción inválida.${NC}"
            sleep 1
            ;;
    esac
done