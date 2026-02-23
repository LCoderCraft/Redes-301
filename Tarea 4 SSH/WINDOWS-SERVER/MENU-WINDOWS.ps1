
. .\FuncionesSSH.ps1

function Show-Menu {
    $menuLoop = $true
    while ($menuLoop) {
        Clear-Host
        Write-Host "===================================================" -ForegroundColor Cyan
        Write-Host "       MENU DE ADMINISTRACION - WINDOWS SERVER     " -ForegroundColor Yellow
        Write-Host "===================================================" -ForegroundColor Cyan
        Write-Host "1. Instalar / Reinstalar OpenSSH"
        Write-Host "2. Configurar IP Estatica y Habilitar Acceso Remoto"
        Write-Host "3. Verificar estado del servicio SSH"
        Write-Host "0. Salir"
        Write-Host "===================================================" -ForegroundColor Cyan
        
        $opcion = Read-Host "Selecciona una opcion [0-3]"
        
        switch ($opcion) {
            '1' { 
                Install-SSHIdempotent
                Pause 
            }
            '2' { 
                $ipAsignada = Set-StaticIP
                if ($ipAsignada) { Enable-RemoteAccess -CurrentIP $ipAsignada } else { Enable-RemoteAccess }
                Pause 
            }
            '3' { 
                Check-SSHStatus
                Pause 
            }
            '0' { 
                Write-Host "Saliendo..." -ForegroundColor Magenta; $menuLoop = $false 
            }
            default { 
                Write-Host "Opcion invalida." -ForegroundColor Red; Start-Sleep -Seconds 2 
            }
        }
    }
}

Show-Menu