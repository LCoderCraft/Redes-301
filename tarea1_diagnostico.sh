#!/bin/bash
clear
echo "============================================"
echo "      DIAGNOSTICO INICIAL ALMALINUX"
echo "============================================"

echo -n "Nombre del equipo: "
echo -e "\e[32m$(hostname)\e[0m"

echo -n "Ip Red Interna:    "
echo -e "\e[32m$(ip -4 addr show enp0s8 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)\e[0m"

echo -n "Espacio en disco:  "
echo -e "\e[32m$(df -h / | awk 'NR==2 {print $4 " libres de " $2}')\e[0m"

echo "============================================"