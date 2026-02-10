Write-Host "--- Iniciando Proceso de Renovación DHCP ---" -ForegroundColor Yellow

# Paso 1: Forzar la liberación y renovación de la IP
Write-Host "[*] Liberando dirección actual..."
ipconfig /release "Ethernet 2" | Out-Null
Start-Sleep -Seconds 1

Write-Host "[*] Solicitando nueva dirección al servidor..."
ipconfig /renew "Ethernet 2" | Out-Null

Write-Host "`n--- Validando Integridad de Parámetros DHCP ---" -ForegroundColor Cyan

# Paso 2: Obtener y validar la nueva configuración
$adapter = Get-NetIPConfiguration -InterfaceAlias "Ethernet 2"
$ip = $adapter.IPv4Address.IPAddress

if ($ip -like "192.168.100.*") {
    Write-Host "[PASÓ] IP recibida correctamente: $ip" -ForegroundColor Green
    Write-Host "[PASÓ] Servidor DNS: $($adapter.DNSServer.ServerAddresses)" -ForegroundColor Green
    Write-Host "[PASÓ] Puerta de Enlace: $($adapter.IPv4DefaultGateway.NextHop)" -ForegroundColor Green
} else {
    Write-Host "[FALLÓ] La IP $ip no pertenece al segmento esperado." -ForegroundColor Red
}