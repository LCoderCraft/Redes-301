# ============================================================
# SCRIPT PRINCIPAL
# Orquestador de Infraestructura y Seguridad (Practica 7)
# Windows Server 2022
# ============================================================
#Requires -RunAsAdministrator

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition

. "$SCRIPT_DIR\config.ps1"
. "$SCRIPT_DIR\http.ps1"
. "$SCRIPT_DIR\ftp_server.ps1"

function Invoke-VerificacionGlobal {
    Write-Host "`n=== RESUMEN DE VERIFICACION DE SERVICIOS ===" -ForegroundColor Cyan
    $puertos = @(
        @{ Servicio="FTP (Control)"; Puerto=21 },
        @{ Servicio="HTTP (Apache/IIS/Nginx)"; Puerto=80 },
        @{ Servicio="HTTPS (SSL Activo)"; Puerto=443 },
        @{ Servicio="HTTP Alterno (Nginx/Tomcat)"; Puerto=8080 }
    )

    foreach ($p in $puertos) {
        $test = Test-NetConnection -ComputerName "localhost" -Port $p.Puerto -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($test) {
            Write-Host "  [ACTIVO] $($p.Servicio) respondiendo en el puerto $($p.Puerto)" -ForegroundColor Green
        } else {
            Write-Host "  [INACTIVO] $($p.Servicio) no detectado en el puerto $($p.Puerto)" -ForegroundColor DarkGray
        }
    }
}

while ($true) {
    Clear-Host
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host "   ORQUESTADOR DE DESPLIEGUE SEGURO - PRACTICA 7      " -ForegroundColor Green
    Write-Host "======================================================" -ForegroundColor Cyan
    
    Write-Host "  INSTALACION HTTP" -ForegroundColor Yellow
    Write-Host "  1. Instalar Apache httpd"
    Write-Host "  2. Instalar Nginx"
    Write-Host "  3. Instalar IIS"
    Write-Host ""
    Write-Host "  SEGURIDAD HTTPS (SSL)" -ForegroundColor Yellow
    Write-Host "  4. Activar HTTPS en Apache"
    Write-Host "  5. Activar HTTPS en Nginx"
    Write-Host "  6. Activar HTTPS en IIS"
    Write-Host ""
    Write-Host "  GESTION DE PUERTOS" -ForegroundColor Yellow
    Write-Host "  7. Cambiar puerto Apache"
    Write-Host "  8. Cambiar puerto Nginx"
    Write-Host ""
    Write-Host "  REPOSITORIO Y VERIFICACION" -ForegroundColor Yellow
    Write-Host "  9. Configurar servidor FTP (Repositorio)"
    Write-Host " 10. Verificacion global de servicios (Resumen)"
    Write-Host "  0. Salir"
    Write-Host "======================================================" -ForegroundColor Cyan

    Write-Host "Selecciona una opcion [0-10]: " -ForegroundColor Green -NoNewline
    $opc = Read-Host

    switch ($opc) {
        "1" { Install-HttpServer -Servidor "Apache" }
        "2" { Install-HttpServer -Servidor "Nginx"  }
        "3" {
            $puerto = Read-Port -Default 80 -Label "Puerto HTTP"
            Install-IIS -Puerto $puerto
        }
        "4" { Set-Https -Servidor "Apache" }
        "5" { Set-Https -Servidor "Nginx"  }
        "6" {
            $puerto = Read-Port -Default 443 -Label "Puerto HTTPS"
            Enable-IISHttps -Puerto $puerto
        }
        "7" { Set-HttpPort -Servidor "Apache" }
        "8" { Set-HttpPort -Servidor "Nginx"  }
        "9" { Invoke-FtpServerSetup }
        "10" { Invoke-VerificacionGlobal }
        "0" {
            Clear-Host
            Write-Host "Saliendo del orquestador..." -ForegroundColor Magenta
            exit 0
        }
        default {
            Write-Host "`n[!] Opcion invalida. Intenta de nuevo." -ForegroundColor Red
            Start-Sleep -Seconds 1
            continue
        }
    }

    Write-Host "`nProceso completado. Presione ENTER para volver al menu principal..." -ForegroundColor DarkGray
    Read-Host | Out-Null
}