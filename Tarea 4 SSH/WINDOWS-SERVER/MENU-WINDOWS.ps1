#Requires -RunAsAdministrator

# IMPORTAR TODAS LAS BIBLIOTECAS DE FUNCIONES
. .\FuncionesSSH.ps1
. .\FuncionesServicios.ps1

# SUBMENÚS

function Show-MenuSSH {
    $sshLoop = $true
    while ($sshLoop) {
        Clear-Host
        Write-Host "===================================================" -ForegroundColor Cyan
        Write-Host "        SUBMENU DE ADMINISTRACION - SSH            " -ForegroundColor Yellow
        Write-Host "===================================================" -ForegroundColor Cyan
        Write-Host "1. Instalar / Reinstalar OpenSSH"
        Write-Host "2. Configurar IP Estatica y Habilitar Acceso Remoto"
        Write-Host "3. Verificar estado del servicio SSH"
        Write-Host "0. Volver al Menu Principal"
        Write-Host "===================================================" -ForegroundColor Cyan
        
        $opcion = Read-Host "Selecciona una opcion [0-3]"
        switch ($opcion) {
            '1' { Install-SSHIdempotent; Pause }
            '2' { 
                $ipAsignada = Set-StaticIP
                if ($ipAsignada) { Enable-RemoteAccess -CurrentIP $ipAsignada } else { Enable-RemoteAccess }
                Pause 
            }
            '3' { Check-SSHStatus; Pause }
            '0' { $sshLoop = $false }
            default { Write-Host "Opcion invalida." -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    }
}

function Show-MenuDHCP {
    $dhcpLoop = $true
    while ($dhcpLoop) {
        Clear-Host
        Write-Host "===================================================" -ForegroundColor Cyan
        Write-Host "        SUBMENU DE ADMINISTRACION - DHCP           " -ForegroundColor Yellow
        Write-Host "===================================================" -ForegroundColor Cyan
        Write-Host "1. Verificar instalacion del Rol"
        Write-Host "2. Instalar o Reinstalar DHCP"
        Write-Host "3. Consulta de servicio (Status)"
        Write-Host "4. Crear / Configurar Ambito DHCP"
        Write-Host "5. Gestionar (Modificar/Eliminar) Ambito Existente"
        Write-Host "6. Monitorear IPs asignadas (Leases)"
        Write-Host "0. Volver al Menu Principal"
        Write-Host "===================================================" -ForegroundColor Cyan
        
        $opcion = Read-Host "Selecciona una opcion [0-6]"
        switch ($opcion) {
            '1' { Mostrar-Verificacion }
            '2' { Instalar-Servicio }
            '3' { Consultar-Estado }
            '4' { Configurar-Ambito }
            '5' { Gestionar-Ambito }
            '6' { Monitorear-IPs }
            '0' { $dhcpLoop = $false }
            default { Write-Host "Opcion invalida." -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    }
}

function Show-MenuDNS {
    $dnsLoop = $true
    while ($dnsLoop) {
        Clear-Host
        Write-Host "===================================================" -ForegroundColor Cyan
        Write-Host "        SUBMENU DE ADMINISTRACION - DNS            " -ForegroundColor Yellow
        Write-Host "===================================================" -ForegroundColor Cyan
        Write-Host "1. Instalar / Reinstalar DNS"
        Write-Host "2. Alta Dominio DNS"
        Write-Host "3. Baja Dominio DNS"
        Write-Host "4. Listar Dominios DNS"
        Write-Host "0. Volver al Menu Principal"
        Write-Host "===================================================" -ForegroundColor Cyan
        
        $opcion = Read-Host "Selecciona una opcion [0-4]"
        switch ($opcion) {
            '1' { Instalar-DNS }
            '2' { Alta-Dominio }
            '3' { Baja-Dominio }
            '4' { Listar-Dominios }
            '0' { $dnsLoop = $false }
            default { Write-Host "Opcion invalida." -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    }
}

# MENÚ PRINCIPAL 

function Show-MenuPrincipal {
    $mainLoop = $true
    while ($mainLoop) {
        Clear-Host
        Write-Host "===================================================" -ForegroundColor Cyan
        Write-Host "   SISTEMA CENTRAL DE ADMINISTRACION - WINDOWS     " -ForegroundColor Green
        Write-Host "===================================================" -ForegroundColor Cyan
        Write-Host "1. Gestion de SSH (Acceso Remoto)"
        Write-Host "2. Gestion de DHCP"
        Write-Host "3. Gestion de DNS"
        Write-Host "0. Salir del Sistema"
        Write-Host "===================================================" -ForegroundColor Cyan
        
        $opcion = Read-Host "Selecciona un servicio [0-3]"
        switch ($opcion) {
            '1' { Show-MenuSSH }
            '2' { Show-MenuDHCP }
            '3' { Show-MenuDNS }
            '0' { Write-Host "Saliendo del sistema central..." -ForegroundColor Magenta; $mainLoop = $false }
            default { Write-Host "Opcion invalida." -ForegroundColor Red; Start-Sleep -Seconds 2 }
        }
    }
}

Show-MenuPrincipal