# ======================================================
# FUNCIONES HTTP (SISTEMA DE APROVISIONAMIENTO ROBUSTO)
# ======================================================

function Verificar-Gestor {
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if(!$choco){ 
        Write-Host "Preparando entorno (Instalando Chocolatey)..." -ForegroundColor Cyan
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $env:Path += ";$env:ALLUSERSPROFILE\chocolatey\bin"
    }
}

function Mostrar-Versiones($paquete){
    Write-Host ""
    Write-Host "  Consultando versiones en el repositorio..." -ForegroundColor DarkGray
    try {
        $url = "https://community.chocolatey.org/api/v2/FindPackagesById()?id='$paquete'"
        $data = Invoke-RestMethod -Uri $url -UseBasicParsing
        $versiones = $data | ForEach-Object {$_.properties.version} | Sort-Object {[version]$_} -Descending | Select-Object -Unique -First 5
        
        Write-Host ""
        Write-Host "  Versiones disponibles para $paquete" -ForegroundColor Cyan
        Write-Host "  ------------------------------------" -ForegroundColor DarkCyan
        $i = 1
        foreach($v in $versiones){
            Write-Host "    $i. $v" -ForegroundColor White
            $i++
        }
        Write-Host ""
        $sel = Read-Host "  Seleccione numero (Enter para latest)"
        if($sel -match "^\d+$"){ return $versiones[[int]$sel-1] }
    } catch {
        Write-Host "  [ERROR] Error de red, usando latest." -ForegroundColor Red
    }
    return "latest"
}

function Puerto-Libre($p){
    $check = Get-NetTCPConnection -LocalPort $p -ErrorAction SilentlyContinue
    return !($check)
}

function Solicitar-Puerto {
    $bloqueados = @(20, 21, 22, 23, 25, 53, 80, 110, 135, 137, 138, 139, 143, 443, 445, 3389)
    do {
        Write-Host ""
        $p = Read-Host "  Puerto de escucha (1-65535)"
        $v = $false
        if($p -match "^[0-9]+$" -and [int]$p -ge 1 -and [int]$p -le 65535){
            $num = [int]$p
            if($bloqueados -contains $num){
                Write-Host "  [ERROR] Puerto $num es de uso critico del sistema y esta bloqueado." -ForegroundColor Red
            } elseif(!(Puerto-Libre $num)) {
                Write-Host "  [ERROR] Puerto $num ya esta en uso por otro proceso." -ForegroundColor Red
            } else {
                Write-Host "  [OK]    Puerto $num disponible." -ForegroundColor Green
                $v = $true
            }
        } else {
            Write-Host "  [ERROR] Formato invalido. Ingrese un numero entre 1 y 65535." -ForegroundColor Red
        }
    } until ($v)
    return [int]$p
}

function Crear-Index($ruta, $serv, $ver, $port) {
    if (!(Test-Path $ruta)) { New-Item -ItemType Directory -Path $ruta -Force | Out-Null }
    
    $html = @"
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>$serv - Servidor Web</title>
  <style>
    body { font-family: Arial, sans-serif; background: #0d1117; color: #c9d1d9;
           display: flex; justify-content: center; align-items: center;
           height: 100vh; margin: 0; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 10px;
            padding: 40px 60px; text-align: center; }
    h1 { color: #58a6ff; }
    span { color: #3fb950; font-weight: bold; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Servidor Web Activo</h1>
    <p>Servidor: <span>$serv</span></p>
    <p>Versión:  <span>$ver</span></p>
    <p>Puerto:   <span>$port</span></p>
    <hr style="border-color:#30363d; margin:20px 0;">
    <small>Aprovisionamiento Automatizado - Práctica 6</small>
  </div>
</body>
</html>
"@
    
    $html | Out-File "$ruta\index.html" -Encoding utf8 -Force
    
    Write-Host "[*] Página index.html generada en $ruta." -ForegroundColor Cyan
}

function Write-Separador {
    Write-Host "  ----------------------------------------------------" -ForegroundColor DarkCyan
}

function Write-Titulo($texto) {
    Write-Host ""
    Write-Host "  ====================================================" -ForegroundColor Cyan
    Write-Host "   $texto" -ForegroundColor White
    Write-Host "  ====================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Instalar-IIS($p){
    Write-Titulo "Instalando IIS en puerto $p"
    Write-Host "  [INFO]  Activando rol Web-Server en Windows..." -ForegroundColor Cyan
    Install-WindowsFeature Web-Server -IncludeManagementTools | Out-Null
    Import-Module WebAdministration

    Get-WebBinding -Name "Default Web Site" -ErrorAction SilentlyContinue | Remove-WebBinding -ErrorAction SilentlyContinue
    New-WebBinding -Name "Default Web Site" -Protocol "http" -Port $p -IPAddress "*" | Out-Null

    Remove-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders" `
        -Name "." -AtElement @{name='X-Powered-By'} -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    New-NetFirewallRule -DisplayName "HTTP-IIS-$p" -Direction Inbound -Protocol TCP `
        -LocalPort $p -Action Allow -ErrorAction SilentlyContinue | Out-Null

    Crear-Index "C:\inetpub\wwwroot" "IIS" "Nativa" $p
    Start-Service W3SVC -ErrorAction SilentlyContinue

    Write-Host "  [OK]    IIS configurado en puerto $p" -ForegroundColor Green
}

function Instalar-Apache($v, $p){
    Write-Titulo "Instalando Apache v$v en puerto $p"

    Write-Host "  [INFO]  Paso 1/5 - Instalando dependencias Visual C++..." -ForegroundColor Cyan
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $vc = "$env:TEMP\vcredist.exe"
    if(!(Test-Path $vc)){
        Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile $vc -UseBasicParsing
    }
    Start-Process $vc -ArgumentList "/install /quiet /norestart" -Wait

    Write-Host "  [INFO]  Paso 2/5 - Pausando IIS para liberar puerto 80..." -ForegroundColor Cyan
    $iisRunning = Get-Service W3SVC -ErrorAction SilentlyContinue
    if($iisRunning -and $iisRunning.Status -eq 'Running'){ Stop-Service W3SVC -Force -ErrorAction SilentlyContinue }

    Write-Host "  [INFO]  Paso 3/5 - Descargando Apache via Chocolatey..." -ForegroundColor Cyan
    $cmd = "choco install apache-httpd -y --force --ignore-dependencies --params `"/installDir:C:\Apache24`""
    if($v -ne "latest"){ $cmd += " --version $v" }
    Invoke-Expression $cmd | Out-Null

    Write-Host "  [INFO]  Paso 4/5 - Buscando y configurando archivos..." -ForegroundColor Cyan
    $rutas = @(
        "C:\Apache24\bin\httpd.exe",
        "$env:APPDATA\Apache24\bin\httpd.exe",
        "C:\tools\Apache24\bin\httpd.exe",
        "C:\ProgramData\chocolatey\lib\apache-httpd\tools\Apache24\bin\httpd.exe"
    )
    $exe = $null
    foreach($r in $rutas){ if(Test-Path $r){ $exe = Get-Item $r; break } }
    if(!$exe){ $exe = Get-ChildItem -Path C:\ -Filter "httpd.exe" -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 1 }

    if($exe){
        $binDir    = $exe.DirectoryName
        $apacheDir = Split-Path $binDir -Parent
        $conf      = Join-Path $apacheDir "conf\httpd.conf"
        $htdocs    = Join-Path $apacheDir "htdocs"

        $content = Get-Content $conf
        $content = $content -replace "Define SRVROOT .*",       "Define SRVROOT `"$($apacheDir.Replace('\','/'))`""
        $content = $content -replace '(?mi)^\s*Listen\s+.*',    "# Puerto anulado por script"
        $content = $content -replace '(?mi)^\s*ServerName\s+.*',"# ServerName anulado por script"
        $content = $content -replace '(?mi)^#?\s*(LoadModule headers_module modules/mod_headers\.so)', '$1'
        $content | Set-Content $conf -Encoding Ascii

        Add-Content $conf "`n# --- CONFIGURACION DEL SCRIPT ---" -Encoding Ascii
        Add-Content $conf "Listen $p"                                         -Encoding Ascii
        Add-Content $conf "ServerName localhost:$p"                           -Encoding Ascii
        Add-Content $conf "ServerTokens Prod"                                 -Encoding Ascii
        Add-Content $conf "ServerSignature Off"                               -Encoding Ascii
        Add-Content $conf "Header always set X-Frame-Options `"SAMEORIGIN`"" -Encoding Ascii
        Add-Content $conf "Header always set X-Content-Type-Options `"nosniff`"" -Encoding Ascii

        Write-Host "  [INFO]  Paso 5/5 - Arrancando servicio..." -ForegroundColor Cyan
        Stop-Process -Name httpd -Force -ErrorAction SilentlyContinue
        Start-Process $exe.FullName -ArgumentList "-k install" -Wait -ErrorAction SilentlyContinue
        Start-Service Apache* -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5

        $apacheRunning = Get-Service Apache* -ErrorAction SilentlyContinue
        if($apacheRunning -and $apacheRunning.Status -eq 'Running' -and !(Puerto-Libre $p)){
            New-NetFirewallRule -DisplayName "HTTP-Apache-$p" -Direction Inbound -Protocol TCP `
                -LocalPort $p -Action Allow -ErrorAction SilentlyContinue | Out-Null
            Crear-Index $htdocs "Apache" $v $p
            Write-Host "  [OK]    Apache corriendo establemente en puerto $p" -ForegroundColor Green
        } else {
            Write-Host "  [ERROR] Apache arranco pero no persiste en el puerto." -ForegroundColor Red
            $errLog = Join-Path $apacheDir "logs\error.log"
            if(Test-Path $errLog){
                Write-Host "  [LOG]   Ultimas lineas del log de error:" -ForegroundColor Yellow
                Get-Content $errLog -Tail 15 -ErrorAction SilentlyContinue | ForEach-Object {
                    Write-Host "          $_" -ForegroundColor DarkYellow
                }
            }
        }
    } else {
        Write-Host "  [ERROR] No se encontraron los binarios de Apache." -ForegroundColor Red
    }

    if($iisRunning -and $iisRunning.Status -eq 'Running'){
        Start-Service W3SVC -ErrorAction SilentlyContinue
        Write-Host "  [INFO]  IIS reactivado." -ForegroundColor DarkGray
    }
}

function Instalar-Nginx($v, $p){
    Write-Titulo "Instalando Nginx v$v en puerto $p"

    Write-Host "  [INFO]  Descargando Nginx via Chocolatey..." -ForegroundColor Cyan
    $cmd = "choco install nginx -y --force"
    if($v -ne "latest"){ $cmd += " --version $v" }
    Invoke-Expression $cmd | Out-Null

    $exe = Get-ChildItem -Path C:\tools, C:\ProgramData\chocolatey, C:\nginx `
        -Filter "nginx.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if(!$exe){ $exe = Get-ChildItem -Path C:\ -Filter "nginx.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 }

    if($exe){
        $nginxDir = $exe.DirectoryName
        $conf     = Join-Path $nginxDir "conf\nginx.conf"
        $htmlDir  = Join-Path $nginxDir "html"

        # Detener nginx ANTES de editar (choco lo arranca automaticamente al instalar)
        Write-Host "  [INFO]  Deteniendo nginx para editar configuracion..." -ForegroundColor Cyan
        Stop-Process -Name nginx -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2

        if(Test-Path $conf){
            $confContent = Get-Content $conf -Raw
            $confContent = $confContent -replace "listen\s+\d+;", "listen $p;"
            [System.IO.File]::WriteAllText($conf, $confContent, [System.Text.Encoding]::ASCII)
            Write-Host "  [OK]    Puerto $p configurado en nginx.conf" -ForegroundColor Green
        }

        Start-Process $exe.FullName -WorkingDirectory $nginxDir

        New-NetFirewallRule -DisplayName "HTTP-Nginx-$p" -Direction Inbound -Protocol TCP `
            -LocalPort $p -Action Allow -ErrorAction SilentlyContinue | Out-Null
        Crear-Index $htmlDir "Nginx" $v $p
        Write-Host "  [OK]    Nginx configurado en puerto $p" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] No se encontraron los binarios de Nginx." -ForegroundColor Red
    }
}

function Limpiar-Servidores {
    Write-Titulo "Limpieza de Servidores HTTP"

    Write-Host "  [INFO]  Deteniendo Nginx..." -ForegroundColor Cyan
    Stop-Process -Name nginx -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "C:\" -Filter "nginx-*" -Directory | ForEach-Object {
        Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
    Get-ChildItem -Path "C:\tools" -Filter "nginx" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  [OK]    Nginx eliminado." -ForegroundColor Green

    Write-Host "  [INFO]  Deteniendo Apache..." -ForegroundColor Cyan
    Stop-Process -Name httpd -Force -ErrorAction SilentlyContinue
    Stop-Service Apache* -ErrorAction SilentlyContinue
    $apacheServices = Get-Service -Name Apache* -ErrorAction SilentlyContinue
    foreach($srv in $apacheServices){
        Start-Process "sc.exe" -ArgumentList "delete $($srv.Name)" -Wait -WindowStyle Hidden
    }
    Start-Sleep -Seconds 2
    Get-ChildItem -Path "C:\tools", "C:\" -Filter "Apache*" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
    if(Test-Path "$env:APPDATA\Apache24"){
        Remove-Item -Path "$env:APPDATA\Apache24" -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  [OK]    Apache eliminado." -ForegroundColor Green

    Write-Host "  [INFO]  Limpiando IIS..." -ForegroundColor Cyan
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    Stop-Service W3SVC -Force -ErrorAction SilentlyContinue
    Get-WebBinding -Name "Default Web Site" -ErrorAction SilentlyContinue | Remove-WebBinding -ErrorAction SilentlyContinue
    New-WebBinding -Name "Default Web Site" -Protocol "http" -Port 80 -IPAddress "*" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "C:\inetpub\wwwroot\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK]    IIS limpiado." -ForegroundColor Green

    Write-Host "  [INFO]  Eliminando reglas de Firewall..." -ForegroundColor Cyan
    Remove-NetFirewallRule -DisplayName "HTTP-IIS-*"    -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "HTTP-Apache-*" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "HTTP-Nginx-*"  -ErrorAction SilentlyContinue
    Write-Host "  [OK]    Reglas de Firewall eliminadas." -ForegroundColor Green

    Write-Separador
    Write-Host "  [OK]    Limpieza completada con exito." -ForegroundColor Green
}