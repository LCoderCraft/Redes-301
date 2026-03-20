#!/bin/bash
# ============================================================
# main.sh - Práctica 7: Orquestador Principal (AlmaLinux)
# ============================================================

# Apagamos temporalmente SELinux para permitir puertos web personalizados
setenforce 0 2>/dev/null

source ./http.sh

while true; do
    clear
    echo -e "\e[36m======================================================\e[0m"
    echo -e "\e[32m   PRÁCTICA 7 - AlmaLinux (Despliegue Híbrido)        \e[0m"
    echo -e "\e[36m======================================================\e[0m"
    echo "  1. Configurar Servidor VSFTPD (Repositorio FTPS)"
    echo "  2. Instalar y Configurar Apache httpd"
    echo "  3. Instalar y Configurar Nginx"
    echo "  4. Instalar y Configurar Tomcat"
    echo "  0. Salir"
    echo -e "\e[36m======================================================\e[0m"
    
    read -p "Selecciona una opción [0-4]: " OPCION

    case $OPCION in
        1) ./ftp_server.sh ;;
        2) Instalar_Servicio "Apache" ;;
        3) Instalar_Servicio "Nginx" ;;
        4) Instalar_Servicio "Tomcat" ;;
        0) echo "Saliendo..."; exit 0 ;;
        *) echo -e "\e[31m[!] Opción inválida.\e[0m"; sleep 1 ;;
    esac

    read -p "Presione ENTER para volver al menú..."
done