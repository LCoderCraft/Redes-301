#!/bin/bash
# ============================================================
# main_p7.sh  -  Practica 7 | AlmaLinux
# Orquestador: Instalación híbrida + SSL/TLS
# ============================================================

source ./p7_functions.sh

verificar_root

while true; do
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}${BOLD}   PRÁCTICA 7 - INFRAESTRUCTURA SSL/TLS - LINUX    ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}SERVIDORES HTTP${NC}                                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  1. Instalar/Configurar Apache  (httpd)              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  2. Instalar/Configurar Nginx                        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  3. Instalar/Configurar Apache Tomcat               ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}SERVIDOR FTP${NC}                                         ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  4. Instalar/Configurar vsftpd (FTP/FTPS)           ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}UTILIDADES${NC}                                           ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  5. Verificar estado de todos los servicios         ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  0. Salir                                           ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    read -p $'\e[1;32mSelecciona una opción [0-5]: \e[0m' opcion

    case $opcion in
        1) menu_apache  ;;
        2) menu_nginx   ;;
        3) menu_tomcat  ;;
        4) menu_vsftpd  ;;
        5) verificar_todos_servicios ;;
        0) clear; echo -e "${MAGENTA}Saliendo...${NC}"; exit 0 ;;
        *) echo -e "${RED}[!] Opción inválida.${NC}"; sleep 1 ;;
    esac
done