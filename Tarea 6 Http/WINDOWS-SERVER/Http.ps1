# ======================================================
# SCRIPT PRINCIPAL
# Aprovisionamiento Web Automatizado
# Windows Server 2022 | Chocolatey
# ======================================================

Import-Module ServerManager -ErrorAction SilentlyContinue
. "$PSScriptRoot\http_functions.ps1"

Clear-Host
Verificar-Gestor

while ($true) {
    Clear-Host
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "   APROVISIONAMIENTO DE SERVIDORES HTTP - WINDOWS  " -ForegroundColor Green
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "  1. Instalar IIS  (Nativo Windows)"
    Write-Host "  2. Instalar Apache  (Seleccionar Version)"
    Write-Host "  3. Instalar Nginx   (Seleccionar Version)"
    Write-Host "  4. Limpiar servidores (Restaurar estado)"
    Write-Host "  0. Salir"
    Write-Host "===================================================" -ForegroundColor Cyan
    
    Write-Host "Selecciona un servidor [0-4]: " -ForegroundColor Green -NoNewline
    $op = Read-Host

    switch ($op) {
        "1" {
            $p = Solicitar-Puerto
            Instalar-IIS $p
        }
        "2" {
            $v = Mostrar-Versiones "apache-httpd"
            $p = Solicitar-Puerto
            Instalar-Apache $v $p
        }
        "3" {
            $v = Mostrar-Versiones "nginx"
            $p = Solicitar-Puerto
            Instalar-Nginx $v $p
        }
        "4" { Limpiar-Servidores }
        "0" {
            Clear-Host
            Write-Host "Saliendo..." -ForegroundColor Magenta
            exit
        }
        default {
            Write-Host "[!] Opcion invalida." -ForegroundColor Red
            Start-Sleep -Seconds 1
            continue 
            
        }
    }

    Write-Host "`nProceso completado. Presione ENTER para volver al menu..." -ForegroundColor DarkGray
    Read-Host | Out-Null
}