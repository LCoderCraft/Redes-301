#!/bin/bash
# ============================================================
# main_p7.sh  -  Practica 7 | AlmaLinux
# Orquestador: Instalación híbrida + SSL/TLS
# ============================================================

source "$(dirname "$0")/p7_functions.sh"

verificar_root

while true; do
    clear
    echo -e "${CYAN}===================================================${NC}"
    echo -e "${GREEN}${BOLD}     PRÁCTICA 7 - INFRAESTRUCTURA SSL/TLS - LINUX  ${NC}"
    echo -e "${CYAN}===================================================${NC}"
    echo -e "  ${YELLOW}-- Servidores HTTP --${NC}"
    echo -e "  1. Instalar Apache  (httpd)"
    echo -e "  2. Instalar Nginx"
    echo -e "  3. Instalar Apache Tomcat"
    echo -e "  ${YELLOW}-- Servidor FTP --${NC}"
    echo -e "  4. Instalar vsftpd  (FTP / FTPS)"
    echo -e "  ${YELLOW}-- Utilidades --${NC}"
    echo -e "  5. Verificar estado de todos los servicios"
    echo -e "  0. Salir"
    echo -e "${CYAN}===================================================${NC}"
    read -p $'\e[1;32mSelecciona una opción [0-5]: \e[0m' opcion

    case $opcion in
        1) instalar_apache  ;;
        2) instalar_nginx   ;;
        3) instalar_tomcat  ;;
        4) instalar_vsftpd  ;;
        5) verificar_todos_servicios ;;
        0) clear; echo -e "${MAGENTA}Saliendo...${NC}"; exit 0 ;;
        *) echo -e "${RED}[!] Opción inválida.${NC}"; sleep 1 ;;
    esac
done