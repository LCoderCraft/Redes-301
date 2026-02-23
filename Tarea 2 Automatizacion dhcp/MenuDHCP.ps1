#Requires -RunAsAdministrator

. .\FuncionesDHCP.ps1

while ($true) {
    Clear-Host
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host " SISTEMA DE ADMINISTRACION DHCP - WINDOWS " -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "1) Verificar instalacion del Rol"
    Write-Host "2) Instalar o Reinstalar DHCP"
    Write-Host "3) Consulta de servicio (Status)"
    Write-Host "4) Crear / Configurar Ambito DHCP"
    Write-Host "5) Gestionar (Modificar/Eliminar) Ambito Existente"
    Write-Host "6) Monitorear IPs asignadas (Leases)"
    Write-Host "7) Salir"
    Write-Host "==========================================" -ForegroundColor Cyan
    $op = Read-Host "Seleccione una opcion"

    switch ($op) {
        '1' { Mostrar-Verificacion }
        '2' { Instalar-Servicio }
        '3' { Consultar-Estado }
        '4' { Configurar-Ambito }
        '5' { Gestionar-Ambito }
        '6' { Monitorear-IPs }
        '7' { Clear-Host; Write-Host "Saliendo del sistema..."; exit }
        default {
            Write-Host "Opcion no valida, intente de nuevo." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}