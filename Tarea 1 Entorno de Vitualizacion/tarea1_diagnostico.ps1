clear-host
Write-Host "============================================" -foregroundcolor cyan
Write-Host "      DIAGNOSTICO INICIAL SISTEMAS" -foregroundcolor cyan
Write-Host "============================================" -foregroundcolor cyan

Write-Host "Nombre del equipo: " -NoNewline; write-host "$env:COMPUTERNAME" -foregroundcolor green

$ip = (Get-NetIPAddress -InterfaceIndex 10 -AddressFamily IPv4).IPAddress
write-host "Ip Red Interna:    " -nonewline; write-host "$ip" -foregroundcolor green

$Disk = Get-PSDrive C
$FreeGB = [math]::Round($Disk.Free/1GB, 2)
$TotalGB = [math]::Round(($Disk.Used + $Disk.Free)/1GB, 2)
write-host "Espacio en disco:  " -nonewline; write-host "$FreeGB GB libres de $TotalGB GB" -foregroundcolor green

Write-Host "============================================" -foregroundcolor cyan