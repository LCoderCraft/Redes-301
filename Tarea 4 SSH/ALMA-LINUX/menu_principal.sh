#!/bin/bash
source ./funciones_red.sh

verificar_root

# MENÚ
while true; do
    clear
    echo -e "${CYAN}===================================================${NC}"
    echo -e "${YELLOW}${BOLD}       MENÚ DE ADMINISTRACIÓN - ALMALINUX          ${NC}"
    echo -e "${CYAN}===================================================${NC}"
    echo -e "  1. Instalar / Reinstalar OpenSSH (Idempotente)"
    echo -e "  2. Configurar IP Estática y Habilitar Acceso Remoto"
    echo -e "  3. Verificar estado del servicio SSH"
    echo -e "  4. Salir"
    echo -e "${CYAN}===================================================${NC}"
    read -p $'\e[1;32mSelecciona una opción [1-4]: \e[0m' opcion

    case $opcion in
        1) 
            instalar_ssh_idempotente
            read -p $'\n\e[1;34mPresiona Enter para continuar...\e[0m' 
            ;;
        2) 
            configurar_ip_estatica && habilitar_acceso_remoto
            read -p $'\n\e[1;34mPresiona Enter para continuar...\e[0m' 
            ;;
        3) 
            verificar_estado_ssh
            read -p $'\n\e[1;34mPresiona Enter para continuar...\e[0m' 
            ;;
        4) 
            echo -e "${MAGENTA}Saliendo...${NC}"; exit 0 
            ;;
        *) 
            echo -e "${RED}Opción inválida.${NC}"; sleep 2 
            ;;
    esac
done