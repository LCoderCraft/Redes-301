function Install-SSHIdempotent {
    Write-Host "--- Instalacion de OpenSSH Server ---" -ForegroundColor Cyan
    $sshCapability = Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

    if ($sshCapability.State -eq "Installed") {
        Write-Host "[!] OpenSSH Server ya esta instalado en el sistema." -ForegroundColor Yellow
        $respuesta = Read-Host "Deseas reinstalarlo? (s/n)"
        if ($respuesta -match "^[sS]$") {
            Write-Host "[*] Desinstalando para reinstalar..." -ForegroundColor Cyan
            Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
            Write-Host "[*] Reinstalando OpenSSH Server..." -ForegroundColor Cyan
            Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
            Write-Host "[+] Reinstalacion completada." -ForegroundColor Green
        } else {
            Write-Host "[*] Omitiendo reinstalacion." -ForegroundColor Yellow
        }
    } else {
        Write-Host "[*] Instalando OpenSSH Server..." -ForegroundColor Cyan
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
        Write-Host "[+] Instalacion completada." -ForegroundColor Green
    }
}

function Set-StaticIP {
    Write-Host "--- Configuracion de IP Estatica para Administracion (SSH) ---" -ForegroundColor Cyan
    
    $adapters = Get-NetAdapter | Where-Object Status -eq 'Up'
    
    if (-not $adapters) {
        Write-Host "[!] No se encontro ningun adaptador activo." -ForegroundColor Red
        return $null
    }

    Write-Host "Adaptadores de red disponibles:" -ForegroundColor Yellow
    $i = 1
    foreach ($a in $adapters) {
        Write-Host "$i) $($a.Name) - $($a.InterfaceDescription)"
        $i++
    }
    
    $seleccion = Read-Host "Selecciona el numero del adaptador para SSH (Normalmente 1 para 'Ethernet')"
    $adapter = $adapters[[int]$seleccion - 1]

    if (-not $adapter) {
        Write-Host "[!] Seleccion invalida." -ForegroundColor Red
        return $null
    }

    Write-Host "Interfaz de administracion seleccionada: $($adapter.Name)" -ForegroundColor Green
    
    $ip = Read-Host "Ingresa IP estatica (ej. 192.168.1.20)"
    $prefix = Read-Host "Ingresa prefijo de subred (ej. 24)"
    
    if ([string]::IsNullOrWhiteSpace($ip) -or [string]::IsNullOrWhiteSpace($prefix)) {
        Write-Host "[!] La IP y el prefijo son obligatorios." -ForegroundColor Red
        return $null
    }

    $gateway = Read-Host "Ingresa Puerta de Enlace [Enter para dejar vacio]"
    $dns = Read-Host "Ingresa servidor DNS [Enter para dejar vacio]"

    Write-Host "[*] Aplicando configuracion..." -ForegroundColor Cyan
    
    Remove-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    Set-NetIPInterface -InterfaceAlias $adapter.Name -Dhcp Disabled -ErrorAction SilentlyContinue | Out-Null
    
    $ipParams = @{
        InterfaceAlias = $adapter.Name
        IPAddress = $ip
        PrefixLength = $prefix
    }
    if (-not [string]::IsNullOrWhiteSpace($gateway)) {
        $ipParams.DefaultGateway = $gateway
    }
    
    New-NetIPAddress @ipParams -ErrorAction SilentlyContinue | Out-Null

    if (-not [string]::IsNullOrWhiteSpace($dns)) {
        Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $dns | Out-Null
    } else {
        Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ResetServerAddresses | Out-Null
    }

    Write-Host "[+] IP configurada correctamente en $($adapter.Name)." -ForegroundColor Green
    return $ip
}

function Enable-RemoteAccess {
    param([string]$CurrentIP)
    
    Write-Host "--- Habilitando Acceso Remoto SSH ---" -ForegroundColor Cyan
    $sshCapability = Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    
    if ($sshCapability.State -ne "Installed") {
        Write-Host "[-] Error: OpenSSH Server NO esta instalado." -ForegroundColor Red
        Write-Host "[-] Por favor, instalalo primero usando la Opcion 1 del menu." -ForegroundColor Red
        return
    }
    
    Write-Host "[*] Configurando el servicio para iniciar automaticamente..." -ForegroundColor Cyan
    Set-Service -Name sshd -StartupType 'Automatic'
    if ((Get-Service sshd).Status -ne 'Running') { Start-Service sshd }
    
    Write-Host "[*] Configurando reglas del Firewall (Puerto 22)..." -ForegroundColor Cyan
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction SilentlyContinue | Out-Null

    if (-not $CurrentIP) {
        $adapter = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
        $CurrentIP = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $adapter.Name -ErrorAction SilentlyContinue).IPAddress
    }

    Write-Host "==================================================" -ForegroundColor Magenta
    Write-Host "[HITO CRITICO ALCANZADO]" -ForegroundColor Green
    Write-Host "Ya puedes abandonar esta consola fisica." -ForegroundColor Green
    Write-Host "Conectate desde tu cliente: ssh Administrator@$CurrentIP" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Magenta
}

function Check-SSHStatus {
    Write-Host "--- Estado del Servicio SSH ---" -ForegroundColor Cyan
    $sshCapability = Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    
    if ($sshCapability.State -eq "Installed") {
        $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            Write-Host "[+] Servicio SSH: INSTALADO y ACTIVO (Corriendo)." -ForegroundColor Green
        } else {
            Write-Host "[-] Servicio SSH: Instalado pero INACTIVO." -ForegroundColor Yellow
        }
        
        $firewall = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
        if ($firewall -and $firewall.Enabled -eq 'True') {
            Write-Host "[+] Firewall: Puerto 22 (SSH) PERMITIDO." -ForegroundColor Green
        } else {
            Write-Host "[-] Firewall: Puerto 22 (SSH) NO permitido." -ForegroundColor Red
        }
    } else {
        Write-Host "[-] OpenSSH Server: NO INSTALADO." -ForegroundColor Red
    }
    Write-Host "-------------------------------" -ForegroundColor Cyan
}