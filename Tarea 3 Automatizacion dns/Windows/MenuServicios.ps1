#Requires -RunAsAdministrator

. .\FuncionesServicios.ps1

while ($true) {
    Clear-Host
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "      SISTEMA DE ADMINISTRACION DHCP      " -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "1) Verificar instalacion del Rol"
    Write-Host "2) Instalar o Reinstalar DHCP"
    Write-Host "3) Consulta de servicio (Status)"
    Write-Host "4) Crear / Configurar Ambito DHCP"
    Write-Host "5) Gestionar (Modificar/Eliminar) Ambito Existente"
    Write-Host "6) Monitorear IPs asignadas (Leases)"
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "      SISTEMA DE ADMINISTRACION DNS       " -ForegroundColor Red
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "7) Instalar / Reinstalar DNS"
    Write-Host "8) Alta Dominio DNS"
    Write-Host "9) Baja Dominio DNS"
    Write-Host "10) Listar Dominios DNS"
    Write-Host "0) Salir"
    Write-Host "==========================================" -ForegroundColor Cyan
    $op = Read-Host "Seleccione una opcion"

    switch ($op) {
        '1' { Mostrar-Verificacion }
        '2' { Instalar-Servicio }
        '3' { Consultar-Estado }
        '4' { Configurar-Ambito }
        '5' { Gestionar-Ambito }
        '6' { Monitorear-IPs }
        '7' { Instalar-DNS }
        '8' { Alta-Dominio }
        '9' { Baja-Dominio }
        '10' { Listar-Dominios }
        '0' { Clear-Host; Write-Host "Saliendo del sistema..."; exit }
        default {
            Write-Host "Opcion no valida, intente de nuevo." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}