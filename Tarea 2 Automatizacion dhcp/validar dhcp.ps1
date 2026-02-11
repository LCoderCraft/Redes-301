Write-Host "--- Iniciando Proceso de Renovacion DHCP ---" -ForegroundColor Yellow

Write-Host "[*] Liberando direccion actual..."
ipconfig /release "Ethernet 2" | Out-Null
Start-Sleep -Seconds 1

Write-Host "[*] Solicitando nueva direccion al servidor..."
ipconfig /renew "Ethernet 2" | Out-Null

Write-Host "`n--- Validando Integridad de Parametros DHCP ---" -ForegroundColor Cyan

$adapter = Get-NetIPConfiguration -InterfaceAlias "Ethernet 2"
$ip = $adapter.IPv4Address.IPAddress

$mac = (Get-NetAdapter -Name "Ethernet 2").MacAddress.Replace("-", ":")
$dhcpServer = (Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "MACAddress='$mac'").DHCPServer

if ([string]::IsNullOrWhiteSpace($ip) -or $ip -like "169.254.*") {
    Write-Host "[FALLO] El servidor no respondio. Se asigno IP APIPA o ninguna: $ip" -ForegroundColor Red
} else {
    Write-Host "[PASO] IP recibida correctamente: $ip" -ForegroundColor Green
    
    if ($dhcpServer) {
        Write-Host "[PASO] Entregada por Servidor DHCP: $dhcpServer" -ForegroundColor Cyan
    } else {
        Write-Host "[!] IP asignada, pero Windows no registro al Servidor DHCP." -ForegroundColor Yellow
    }
    
    Write-Host "[PASO] Servidor DNS: $($adapter.DNSServer.ServerAddresses)" -ForegroundColor Green
    Write-Host "[PASO] Puerta de Enlace: $($adapter.IPv4DefaultGateway.NextHop)" -ForegroundColor Green
}