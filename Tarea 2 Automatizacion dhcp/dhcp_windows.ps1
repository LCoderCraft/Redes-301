# ==========================================================
# SISTEMA DE CONFIGURACION AUTOMATIZADA DHCP EN WINDOWS
# ==========================================================
Clear-Host

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SISTEMA DE CONFIGURACION AUTOMATIZADA DHCP WINDOWS     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Logica de Instalacion 
Write-Host "`n[*] Verificando la presencia del rol DHCP Server..." -NoNewline
$dhcpFeature = Get-WindowsFeature -Name DHCP
if ($dhcpFeature.Installed -eq $false) {
    Write-Host " No encontrado." -ForegroundColor Red
    Write-Host "[*] Instalando de forma desatendida..." -ForegroundColor Yellow
    Install-WindowsFeature -Name DHCP -IncludeManagementTools | Out-Null
    Write-Host "[+] Instalacion completada." -ForegroundColor Green
} else {
    Write-Host " Rol ya instalado (Idempotente)." -ForegroundColor Green
}

# --- FUNCION DE VALIDACION DE IP ---
function Validar-IPv4 {
    param([string]$IP)
    return $IP -as [ipaddress] -ne $null
}

# 2. Orquestacion de Configuracion Dinamica
Write-Host "`n--- Configuracion de Parametros de Red ---" -ForegroundColor Cyan
$ScopeName = Read-Host "Nombre descriptivo del Ambito (Scope)"

do { $StartIP = Read-Host "IP inicial del rango [ej. 192.168.100.50]" } until (Validar-IPv4 $StartIP)
do { $EndIP   = Read-Host "IP Final del rango [ej. 192.168.100.150]" } until (Validar-IPv4 $EndIP)
$LeaseTime    = Read-Host "Tiempo de concesion (ej: 08:00:00)"
do { $Gateway = Read-Host "Puerta de enlace (Router) [ej. 192.168.100.1]" } until (Validar-IPv4 $Gateway)
do { $DNS     = Read-Host "IP del DNS [ej. 192.168.100.20]" } until (Validar-IPv4 $DNS)

# 3. Creacion Idempotente y Logica Dinamica
$ScopeId = (($StartIP -split "\.")[0..2] -join ".") + ".0"
Write-Host "`n[*] Procesando Ambito: $ScopeId" -ForegroundColor Yellow

$existe = Get-DhcpServerv4Scope -ScopeId $ScopeId -ErrorAction SilentlyContinue

if (-not $existe) {
    try {
        # Crear el ambito
        Add-DhcpServerv4Scope -Name $ScopeName -StartRange $StartIP -EndRange $EndIP -SubnetMask 255.255.255.0 -LeaseDuration $LeaseTime -State Active
        
        # Configuracion de Opciones
        Set-DhcpServerv4OptionValue -ScopeId $ScopeId -OptionId 3 -Value $Gateway -Force
        Set-DhcpServerv4OptionValue -ScopeId $ScopeId -OptionId 6 -Value $DNS -Force
        
        Write-Host "[+] Ambito y opciones configurados exitosamente." -ForegroundColor Green
    } catch {
        Write-Host "[!] Error critico: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "[*] El ambito ya existe. Omitiendo pasos de creacion." -ForegroundColor Cyan
}

# 4. Modulo de Monitoreo y Validacion de Estado
Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "           DIAGNOSTICO DE ESTADO EN TIEMPO REAL           " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$service = Get-Service -Name DHCPServer
$color = if ($service.Status -eq 'Running') {"Green"} else {"Red"}
Write-Host "Estado del servicio: " -NoNewline
Write-Host $service.Status -ForegroundColor $color

Write-Host "`nListado de concesiones (leases) activas para el ambito ${ScopeId}:"
$leases = Get-DhcpServerv4Lease -ScopeId $ScopeId -ErrorAction SilentlyContinue
if ($leases) {
    $leases | Select-Object IPAddress, ClientId, HostName | Format-Table -AutoSize
} else {
    Write-Host "Sin concesiones activas actualmente." -ForegroundColor Gray
}