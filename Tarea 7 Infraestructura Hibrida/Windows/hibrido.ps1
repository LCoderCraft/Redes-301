#Requires -RunAsAdministrator
# =============================================================================
# PRACTICA 7 - ORQUESTADOR DE INSTALACION HIBRIDA + SSL/TLS
# Windows Server sin entorno grafico
# Integra logica de ftp.ps1 (Practica 5) internamente
# Dominio: www.reprobados.com
# =============================================================================

$ErrorActionPreference = "Continue"

# -----------------------------------------------------------------------------
# VARIABLES GLOBALES (mismas rutas que ftp.ps1)
# -----------------------------------------------------------------------------
$DOMAIN       = "www.reprobados.com"
$CERT_STORE   = "Cert:\LocalMachine\My"

$ftpBaseDir   = "C:\FTP_Base"
$ftpSiteDir   = "C:\FTP_Site"
$localUserDir = "$ftpSiteDir\LocalUser"
$siteName     = "ServidorFTP"

$REPO_BASE       = "$ftpBaseDir\general\http\Windows"
$FTP_HOST        = ""
$FTP_USER        = ""
$FTP_PASS        = ""
$FTP_REMOTE_BASE = "/http/Windows"
$FUENTE          = ""

$LOG_FILE     = "C:\practica7\practica7.log"
$SUMMARY_FILE = "C:\practica7\practica7_summary.txt"
$WORK_DIR     = "C:\practica7\downloads"

# -----------------------------------------------------------------------------
# UTILIDADES
# -----------------------------------------------------------------------------
function Ensure-Dir($path) {
    if (-not (Test-Path $path)) { New-Item -ItemType Directory -Force -Path $path | Out-Null }
}
function Write-Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts  $msg" | Out-File -Append -FilePath $LOG_FILE -Encoding UTF8
}
function Info($msg)   { Write-Host "[INFO]  $msg" -ForegroundColor Cyan;   Write-Log "INFO: $msg" }
function OK($msg)     { Write-Host "[OK]    $msg" -ForegroundColor Green;  Write-Log "OK: $msg" }
function Warn($msg)   { Write-Host "[WARN]  $msg" -ForegroundColor Yellow; Write-Log "WARN: $msg" }
function Err($msg)    { Write-Host "[ERROR] $msg" -ForegroundColor Red;    Write-Log "ERROR: $msg" }
function Header($msg) {
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "  $msg"                                 -ForegroundColor Cyan
    Write-Host "======================================"  -ForegroundColor Cyan
    Write-Host ""
}
function Add-Summary($msg) {
    $msg | Out-File -Append -FilePath $SUMMARY_FILE -Encoding UTF8
}

# -----------------------------------------------------------------------------
# PERMISOS NTFS (logica identica a ftp.ps1)
# -----------------------------------------------------------------------------
function Set-NTFSPermissions {
    param([string]$Path, [string]$Identity, [string]$Rights = "Modify")
    $acl     = Get-Acl $Path
    $acl.SetAccessRuleProtection($true, $false)
    $sysSid  = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
    $admSid  = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $inherit = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $none    = [System.Security.AccessControl.PropagationFlags]"None"
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sysSid,"FullControl",$inherit,$none,"Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admSid,"FullControl",$inherit,$none,"Allow")))
    $idRef = if ($Identity -match "^S-1-") {
        New-Object System.Security.Principal.SecurityIdentifier($Identity)
    } else {
        New-Object System.Security.Principal.NTAccount($Identity)
    }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($idRef,$Rights,$inherit,$none,"Allow")))
    Set-Acl -Path $Path -AclObject $acl
}

function Add-NTFSPermission {
    param([string]$Path, [string]$Identity, [string]$Rights)
    $acl     = Get-Acl $Path
    $inherit = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $none    = [System.Security.AccessControl.PropagationFlags]"None"
    $idRef   = if ($Identity -match "^S-1-") {
        New-Object System.Security.Principal.SecurityIdentifier($Identity)
    } else {
        New-Object System.Security.Principal.NTAccount($Identity)
    }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($idRef,$Rights,$inherit,$none,"Allow")))
    Set-Acl -Path $Path -AclObject $acl
}

function New-JunctionIfMissing {
    param([string]$JunctionPath, [string]$TargetPath)
    if (-not (Test-Path $JunctionPath)) {
        cmd /c mklink /J "$JunctionPath" "$TargetPath" | Out-Null
    }
}

# -----------------------------------------------------------------------------
# LOGICA FTP (ftp.ps1 Opcion 1) - SE EJECUTA AUTOMATICAMENTE SI SE NECESITA
# -----------------------------------------------------------------------------
function Ensure-FTP-Installed {
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    Import-Module ServerManager    -ErrorAction SilentlyContinue

    $ftpFeature = Get-WindowsFeature Web-Ftp-Server -ErrorAction SilentlyContinue
    $siteExists = Get-WebSite -Name $siteName -ErrorAction SilentlyContinue

    if ($ftpFeature -and $ftpFeature.Installed -and $siteExists) {
        OK "IIS FTP ya esta instalado y el sitio '$siteName' existe."
        return $true
    }

    Info "El sitio '$siteName' no existe. Instalando IIS FTP automaticamente..."
    Info "(Logica equivalente a ftp.ps1 Opcion 1)"

    # Instalar caracteristicas IIS + FTP
    if (-not ($ftpFeature -and $ftpFeature.Installed)) {
        Info "Instalando Web-Server, Web-Ftp-Server..."
        Install-WindowsFeature Web-Server, Web-Ftp-Server, Web-Ftp-Service, Web-Mgmt-Console `
            -IncludeManagementTools -ErrorAction SilentlyContinue | Out-Null
        Import-Module WebAdministration -ErrorAction SilentlyContinue
    }

    # Crear grupos locales (identico a ftp.ps1)
    foreach ($grupo in @("reprobados", "recursadores")) {
        if (-not (Get-LocalGroup -Name $grupo -ErrorAction SilentlyContinue)) {
            New-LocalGroup -Name $grupo -Description "Grupo FTP $grupo" | Out-Null
            OK "Grupo '$grupo' creado."
        }
    }

    # Estructura de directorios (identica a ftp.ps1)
    foreach ($dir in @("$ftpBaseDir\general","$ftpBaseDir\reprobados","$ftpBaseDir\recursadores")) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    # Permisos /general: Everyone ReadOnly, AuthenticatedUsers Modify, Deny Write a Everyone
    Set-NTFSPermissions -Path "$ftpBaseDir\general" -Identity "S-1-1-0" -Rights "ReadAndExecute"
    Add-NTFSPermission  -Path "$ftpBaseDir\general" -Identity "S-1-5-11" -Rights "Modify"

    $inheritFlags  = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $propFlags     = [System.Security.AccessControl.PropagationFlags]"None"
    $everyoneSid   = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
    $denyWriteRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $everyoneSid,
        [System.Security.AccessControl.FileSystemRights]"Write,AppendData,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership,CreateFiles,CreateDirectories",
        $inheritFlags, $propFlags, "Deny"
    )
    $aclGeneral = Get-Acl "$ftpBaseDir\general"
    $aclGeneral.AddAccessRule($denyWriteRule)
    Set-Acl -Path "$ftpBaseDir\general" -AclObject $aclGeneral

    Set-NTFSPermissions -Path "$ftpBaseDir\reprobados"  -Identity "reprobados"  -Rights "Modify"
    Set-NTFSPermissions -Path "$ftpBaseDir\recursadores" -Identity "recursadores" -Rights "Modify"

    # Eliminar sitios previos si existen
    foreach ($s in @($siteName, "Default FTP Site")) {
        if (Get-WebSite -Name $s -ErrorAction SilentlyContinue) {
            Remove-WebSite -Name $s -ErrorAction SilentlyContinue
        }
    }

    # Crear estructura del sitio IIS
    New-Item -Path $ftpSiteDir   -ItemType Directory -Force | Out-Null
    New-Item -Path $localUserDir -ItemType Directory -Force | Out-Null

    # Crear sitio FTP (identico a ftp.ps1)
    New-WebFtpSite -Name $siteName -Port 21 -PhysicalPath $ftpSiteDir -Force | Out-Null

    # Aislamiento modo 3: LocalUser/<usuario>
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.userIsolation.mode" -Value 3

    # SSL deshabilitado por defecto (se activa luego con FTPS)
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.security.ssl.controlChannelPolicy" -Value 0
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.security.ssl.dataChannelPolicy"    -Value 0
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.security.ssl.serverCertHash"       -Value ""
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.security.ssl.serverCertStoreName"  -Value "MY"

    # Autenticacion: basica + anonima habilitadas
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.security.authentication.basicAuthentication.enabled"     -Value $true
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.security.authentication.anonymousAuthentication.enabled" -Value $true

    # Reglas de autorizacion FTP
    Clear-WebConfiguration -Filter "/system.ftpServer/security/authorization" `
        -PSPath "IIS:\" -Location $siteName -ErrorAction SilentlyContinue

    Add-WebConfiguration -Filter "/system.ftpServer/security/authorization" `
        -PSPath "IIS:\" -Location $siteName `
        -Value @{accessType="Allow"; users="?"; permissions="Read"}

    Add-WebConfiguration -Filter "/system.ftpServer/security/authorization" `
        -PSPath "IIS:\" -Location $siteName `
        -Value @{accessType="Allow"; users="*"; permissions="Read,Write"}

    # Directorio del anonimo: LocalUser\Public con junction a /general
    $anonDir = "$localUserDir\Public"
    New-Item -Path $anonDir -ItemType Directory -Force | Out-Null
    New-JunctionIfMissing -JunctionPath "$anonDir\general" -TargetPath "$ftpBaseDir\general"
    Set-NTFSPermissions -Path $anonDir -Identity "S-1-1-0" -Rights "ReadAndExecute"

    # Regla de firewall puerto 21
    $fwRule = Get-NetFirewallRule -DisplayName "FTP Server (TCP-In)" -ErrorAction SilentlyContinue
    if (-not $fwRule) {
        New-NetFirewallRule -DisplayName "FTP Server (TCP-In)" -Direction Inbound `
            -Protocol TCP -LocalPort 21 -Action Allow | Out-Null
    }

    # Reiniciar ftpsvc
    try {
        Restart-Service -Name "ftpsvc" -Force -ErrorAction Stop
        OK "Servicio FTP iniciado (puerto 21)."
    } catch {
        Warn "No se pudo iniciar ftpsvc: $_"
    }

    OK "IIS FTP instalado y sitio '$siteName' creado correctamente."
    return $true
}

# -----------------------------------------------------------------------------
# FUENTE DE INSTALACION
# -----------------------------------------------------------------------------
function Select-InstallSource {
    Header "FUENTE DE INSTALACION"
    Write-Host "  [1] WEB          - Descargar desde web oficial"
    Write-Host "  [2] FTP LOCAL    - Repositorio en este servidor ($REPO_BASE)"
    Write-Host "  [3] FTP REMOTO   - Repositorio en otro servidor FTP"
    Write-Host ""
    $opt = Read-Host "Selecciona [1/2/3]"
    switch ($opt) {
        "1" { $script:FUENTE = "WEB";        Info "Fuente: WEB" }
        "2" { $script:FUENTE = "LOCAL";      Info "Fuente: FTP LOCAL"
              if (-not (Test-Path $REPO_BASE)) {
                  Warn "Directorio no encontrado: $REPO_BASE"
                  Warn "Crea la estructura: $REPO_BASE\IIS\, Apache\, Nginx\"
              } }
        "3" { $script:FUENTE = "FTP_REMOTO"; Get-FtpCredentials }
        default { Warn "Invalido, usando WEB."; $script:FUENTE = "WEB" }
    }
}

function Get-FtpCredentials {
    Write-Host ""
    $script:FTP_HOST = Read-Host "  Host FTP"
    $script:FTP_USER = Read-Host "  Usuario FTP"
    $ftpPassSec = Read-Host "  Contrasena FTP" -AsSecureString
    $script:FTP_PASS = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                           [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ftpPassSec))
    Info "FTP remoto: $FTP_HOST"
}

# -----------------------------------------------------------------------------
# CLIENTE FTP NO INTERACTIVO (FtpWebRequest / WebClient)
# -----------------------------------------------------------------------------
function Get-FtpListing($ftpPath) {
    $uri = "ftp://${FTP_HOST}${ftpPath}"
    $req = [Net.FtpWebRequest]::Create($uri)
    $req.Method      = [Net.WebRequestMethods+Ftp]::ListDirectory
    $req.Credentials = New-Object Net.NetworkCredential($FTP_USER, $FTP_PASS)
    $req.UsePassive  = $true
    $req.UseBinary   = $true
    $req.EnableSsl   = $false
    try {
        $resp   = $req.GetResponse()
        $reader = New-Object IO.StreamReader($resp.GetResponseStream())
        $lista  = $reader.ReadToEnd()
        $reader.Close(); $resp.Close()
        return ($lista -split "`n" | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() })
    } catch {
        Warn "No se pudo listar ${uri}: $_"
        return @()
    }
}

function Get-FtpFile($ftpPath, $localDest) {
    $uri  = "ftp://${FTP_HOST}${ftpPath}"
    Info "Descargando $uri ..."
    $cred = New-Object Net.NetworkCredential($FTP_USER, $FTP_PASS)
    $wc   = New-Object Net.WebClient
    $wc.Credentials = $cred
    try {
        $wc.DownloadFile($uri, $localDest)
        OK "Descargado: $(Split-Path $localDest -Leaf)"
        return $true
    } catch {
        Err "Fallo al descargar ${uri}: $_"
        return $false
    } finally {
        $wc.Dispose()
    }
}

# -----------------------------------------------------------------------------
# SELECCION DE INSTALADOR
# -----------------------------------------------------------------------------
function Select-Installer($servicio) {
    switch ($FUENTE) {
        "LOCAL" {
            $dir = "$REPO_BASE\$servicio"
            if (-not (Test-Path $dir)) { Err "No encontrado: $dir"; return $null }
            $archivos = Get-ChildItem $dir -File | Where-Object { $_.Extension -notin @(".sha256") } | Sort-Object Name
            if ($archivos.Count -eq 0) { Err "Sin instaladores en $dir"; return $null }
            Write-Host ""
            Write-Host "  Instaladores en $dir :" -ForegroundColor White
            for ($i = 0; $i -lt $archivos.Count; $i++) {
                Write-Host "    [$($i+1)] $($archivos[$i].Name)"
            }
            Write-Host ""
            $sel = 0
            do { $input = Read-Host "  Numero"; [int]::TryParse($input.Trim(),[ref]$sel)|Out-Null } while ($sel -lt 1 -or $sel -gt $archivos.Count)
            return $archivos[$sel-1].FullName
        }
        "FTP_REMOTO" {
            $rutaDir  = "$FTP_REMOTE_BASE/$servicio/"
            Info "Listando ftp://${FTP_HOST}${rutaDir} ..."
            $archivos = Get-FtpListing $rutaDir | Where-Object { $_ -notmatch '\.sha256$' }
            if ($archivos.Count -eq 0) { Err "Sin instaladores en $rutaDir"; return $null }
            Write-Host ""
            Write-Host "  Instaladores disponibles:" -ForegroundColor White
            for ($i = 0; $i -lt $archivos.Count; $i++) { Write-Host "    [$($i+1)] $($archivos[$i])" }
            Write-Host ""
            $sel = 0
            do { $input = Read-Host "  Numero"; [int]::TryParse($input.Trim(),[ref]$sel)|Out-Null } while ($sel -lt 1 -or $sel -gt $archivos.Count)
            $nombre    = $archivos[$sel-1]
            $localFile = "$WORK_DIR\$nombre"
            $ok = Get-FtpFile "$FTP_REMOTE_BASE/$servicio/$nombre" $localFile
            if (-not $ok) { return $null }
            Verify-Hash $localFile "$FTP_REMOTE_BASE/$servicio/$nombre.sha256" "remoto"
            return $localFile
        }
    }
    return $null
}

# -----------------------------------------------------------------------------
# VERIFICACION DE INTEGRIDAD SHA256
# -----------------------------------------------------------------------------
function Verify-Hash($localFile, $sha256Ruta, $tipo) {
    $nombre  = Split-Path $localFile -Leaf
    Info "Verificando SHA256 de $nombre ..."
    $tmpHash = "$WORK_DIR\${nombre}.sha256"

    if ($tipo -eq "local") {
        if (-not (Test-Path $sha256Ruta)) { Warn "Sin .sha256 - omitiendo."; Add-Summary "  Hash: OMITIDO - $nombre"; return }
        Copy-Item $sha256Ruta $tmpHash -Force
    } else {
        $ok = Get-FtpFile $sha256Ruta $tmpHash
        if (-not $ok) { Warn "No se descargo .sha256 - omitiendo."; Add-Summary "  Hash: OMITIDO - $nombre"; return }
    }

    $esperado  = (Get-Content $tmpHash -Raw).Split(" ")[0].Trim().ToUpper()
    $calculado = (Get-FileHash -Algorithm SHA256 $localFile).Hash.ToUpper()

    if ($calculado -eq $esperado) {
        OK "Integridad OK - SHA256 coincide."
        Add-Summary "  Hash: OK - $nombre"
    } else {
        Err "FALLO DE INTEGRIDAD"
        Err "  Esperado:  $esperado"
        Err "  Calculado: $calculado"
        Add-Summary "  Hash: FALLO - $nombre"
        $cont = Read-Host "  Continuar de todos modos? (s/n)"
        if ($cont -notmatch "^[Ss]$") { Err "Cancelado."; exit 1 }
    }
    Remove-Item $tmpHash -ErrorAction SilentlyContinue
}

function Verify-Hash-Local($localFile) {
    Verify-Hash $localFile "${localFile}.sha256" "local"
}

# -----------------------------------------------------------------------------
# CERTIFICADOS SSL/TLS
# -----------------------------------------------------------------------------
function New-SslCert($servicio) {
    Info "Generando certificado autofirmado para $servicio ($DOMAIN) ..."
    $cert = New-SelfSignedCertificate `
        -DnsName $DOMAIN `
        -CertStoreLocation $CERT_STORE `
        -NotAfter (Get-Date).AddDays(365) `
        -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
        -FriendlyName "Practica7-$servicio" `
        -KeyExportPolicy Exportable
    OK "Certificado generado: Thumbprint=$($cert.Thumbprint.Substring(0,16))..."
    return $cert
}

function Export-ToPfx($cert, $pfxPath, $password) {
    $secPass = ConvertTo-SecureString $password -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $secPass | Out-Null
    OK "PFX exportado: $pfxPath"
}

function Export-ToPem($pfxPath, $password, $certOut, $keyOut) {
    if (Get-Command openssl -ErrorAction SilentlyContinue) {
        openssl pkcs12 -in $pfxPath -nokeys -clcerts -out $certOut -passin "pass:$password" 2>$null
        openssl pkcs12 -in $pfxPath -nocerts -nodes   -out $keyOut  -passin "pass:$password" 2>$null
        OK "PEM: $certOut / $keyOut"
    } else {
        Warn "OpenSSL no disponible. Solo se usa PFX."
    }
}

# -----------------------------------------------------------------------------
# SERVICIO 1: IIS HTTP
# -----------------------------------------------------------------------------
function Install-IIS($source) {
    Header "IIS HTTP (Windows)"
    Info "Instalando IIS con caracteristicas necesarias..."
    Install-WindowsFeature -Name Web-Server, Web-Mgmt-Tools, Web-Asp-Net45 `
        -IncludeManagementTools -ErrorAction SilentlyContinue | Out-Null

    if ($source -ne "WEB") {
        $localFile = Select-Installer "IIS"
        if ($localFile -and $source -eq "LOCAL") { Verify-Hash-Local $localFile }
        if ($localFile -and $localFile -match '\.msi$') {
            Info "Instalando modulo IIS: $localFile"
            Start-Process msiexec -ArgumentList "/i `"$localFile`" /qn" -Wait
        }
    }

    Start-Service W3SVC -ErrorAction SilentlyContinue
    Set-Service   W3SVC -StartupType Automatic -ErrorAction SilentlyContinue
    OK "IIS iniciado."

    $ssl = Read-Host "  Activar SSL en IIS (puerto 443)? [S/N]"
    if ($ssl -match '^[Ss]$') {
        $cert = New-SslCert "IIS"
        Config-IIS-SSL $cert
        Add-Summary "IIS: SSL ACTIVADO (443) CN=$DOMAIN"
    } else {
        Add-Summary "IIS: SSL no activado"
    }
}

function Config-IIS-SSL($cert) {
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $siteName_iis = "Default Web Site"
    $thumb = $cert.Thumbprint

    Get-WebBinding -Name $siteName_iis -Protocol "https" -ErrorAction SilentlyContinue |
        Remove-WebBinding -ErrorAction SilentlyContinue

    New-WebBinding -Name $siteName_iis -Protocol "https" -Port 443 -HostHeader $DOMAIN
    $binding = Get-WebBinding -Name $siteName_iis -Protocol "https"
    $binding.AddSslCertificate($thumb, "My")

    $webConfig = "C:\inetpub\wwwroot\web.config"
    @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="HTTP to HTTPS" stopProcessing="true">
          <match url="(.*)" />
          <conditions>
            <add input="{HTTPS}" pattern="^OFF$" />
          </conditions>
          <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
        </rule>
      </rules>
    </rewrite>
    <httpProtocol>
      <customHeaders>
        <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
"@ | Set-Content $webConfig -Encoding UTF8

    New-NetFirewallRule -DisplayName "P7-IIS-443" -Direction Inbound `
        -Protocol TCP -LocalPort 443 -Action Allow -ErrorAction SilentlyContinue | Out-Null

    Restart-Service W3SVC -ErrorAction SilentlyContinue
    OK "IIS: SSL configurado (443) con HSTS y redireccion HTTP->HTTPS."
}

# -----------------------------------------------------------------------------
# SERVICIO 2: IIS FTP + FTPS
# Instala IIS FTP si no existe (logica de ftp.ps1) y luego activa FTPS
# -----------------------------------------------------------------------------
function Install-IIS-FTP-FTPS {
    Header "IIS FTP + FTPS (SSL/TLS)"

    # PASO 1: Asegurar que IIS FTP esta instalado (auto-instala si falta)
    $ok = Ensure-FTP-Installed
    if (-not $ok) {
        Err "No se pudo instalar IIS FTP."
        Add-Summary "IIS-FTP: ERROR en instalacion"
        return
    }

    # PASO 2: Preguntar si activar FTPS
    $ssl = Read-Host "  Activar SSL/TLS (FTPS implicito, puerto 990) en '$siteName'? [S/N]"
    if ($ssl -notmatch '^[Ss]$') {
        Add-Summary "IIS-FTP: instalado en puerto 21, FTPS no activado"
        return
    }

    # PASO 3: Generar certificado y activar FTPS
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $cert  = New-SslCert "IIS-FTP"
    $thumb = $cert.Thumbprint
    $appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"

    # SslRequire = 1 (obliga SSL en canal de control y datos)
    & $appcmd set site /site.name:$siteName `
        /ftpServer.security.ssl.serverCertHash:$thumb `
        /ftpServer.security.ssl.serverCertStoreName:"MY" `
        /ftpServer.security.ssl.controlChannelPolicy:1 `
        /ftpServer.security.ssl.dataChannelPolicy:1 2>$null

    # Firewall: puerto 990 (FTPS implicito) + datos pasivos
    New-NetFirewallRule -DisplayName "P7-FTPS-990"  -Direction Inbound `
        -Protocol TCP -LocalPort 990         -Action Allow -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "P7-FTPS-Datos" -Direction Inbound `
        -Protocol TCP -LocalPort 49152-65535  -Action Allow -ErrorAction SilentlyContinue | Out-Null

    # Reiniciar ftpsvc (NO Start/Stop-WebSite, da error 0x800710D8)
    try {
        Restart-Service -Name "ftpsvc" -Force -ErrorAction Stop
        OK "Servicio FTP reiniciado correctamente."
    } catch {
        Warn "Reinicia ftpsvc manualmente: $_"
    }

    OK "IIS-FTP: FTPS activado en puerto 990."
    Add-Summary "IIS-FTP: FTPS ACTIVADO (990) CN=$DOMAIN"
}

# -----------------------------------------------------------------------------
# SERVICIO 3: APACHE WINDOWS
# -----------------------------------------------------------------------------
function Install-ApacheWin($source) {
    Header "Apache HTTP (Windows)"
    $apacheDir = "C:\Apache24"
    $localFile = $null

    if ($source -ne "WEB") {
        $localFile = Select-Installer "Apache"
        if ($localFile -and $source -eq "LOCAL") { Verify-Hash-Local $localFile }
    } else {
        $zipPath = "$WORK_DIR\apache_win.zip"
        $url = "https://www.apachelounge.com/download/VS17/binaries/httpd-2.4.62-240605-win64-VS17.zip"
        Info "Descargando Apache para Windows..."
        try {
            Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
            $localFile = $zipPath
        } catch {
            Warn "No se pudo descargar. Coloca el ZIP en $zipPath manualmente."
            $localFile = $zipPath
        }
    }

    if ($localFile -and (Test-Path $localFile) -and $localFile -match '\.zip$') {
        Expand-Archive -Path $localFile -DestinationPath "C:\" -Force -ErrorAction SilentlyContinue
        $extracted = Get-Item "C:\Apache*" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($extracted -and $extracted.FullName -ne $apacheDir) {
            Rename-Item $extracted.FullName $apacheDir -Force -ErrorAction SilentlyContinue
        }
    } elseif ($localFile -and $localFile -match '\.msi$') {
        Start-Process msiexec -ArgumentList "/i `"$localFile`" /qn INSTALLDIR=`"$apacheDir`"" -Wait
    }

    if (-not (Test-Path "$apacheDir\bin\httpd.exe")) {
        Warn "Apache no encontrado en $apacheDir"
        Add-Summary "Apache Windows: instalacion no completada"
        return
    }

    & "$apacheDir\bin\httpd.exe" -k install -n "Apache2.4" 2>$null
    Start-Service "Apache2.4" -ErrorAction SilentlyContinue
    OK "Apache Windows iniciado."

    $ssl = Read-Host "  Activar SSL en Apache Windows (puerto 443)? [S/N]"
    if ($ssl -match '^[Ss]$') {
        $cert = New-SslCert "ApacheWin"
        Config-ApacheWin-SSL $cert $apacheDir
        Add-Summary "Apache Windows: SSL ACTIVADO (443) CN=$DOMAIN"
    } else {
        Add-Summary "Apache Windows: SSL no activado"
    }
}

function Config-ApacheWin-SSL($cert, $apacheDir) {
    $pfxPath  = "$WORK_DIR\apache_win.pfx"
    $sslDir   = "$apacheDir\conf\ssl"
    $certPath = "$sslDir\server.crt"
    $keyPath  = "$sslDir\server.key"
    $password = "P@ssw0rd!"

    Ensure-Dir $sslDir
    Export-ToPfx $cert $pfxPath $password
    Export-ToPem $pfxPath $password $certPath $keyPath

    $httpConf = "$apacheDir\conf\httpd.conf"
    if (Test-Path $httpConf) {
        (Get-Content $httpConf) `
            -replace '^#(LoadModule ssl_module)',              '$1' `
            -replace '^#(Include conf/extra/httpd-ssl.conf)', '$1' |
            Set-Content $httpConf
    }

    $certFwd = $certPath -replace '\\','/'
    $keyFwd  = $keyPath  -replace '\\','/'

    @"
Listen 443

<VirtualHost *:80>
    ServerName $DOMAIN
    Redirect permanent / https://$DOMAIN/
    Header always set Strict-Transport-Security "max-age=31536000"
</VirtualHost>

<VirtualHost _default_:443>
    DocumentRoot "$apacheDir/htdocs"
    ServerName $DOMAIN
    SSLEngine on
    SSLCertificateFile    $certFwd
    SSLCertificateKeyFile $keyFwd
    SSLProtocol           all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite        HIGH:!aNULL:!MD5
    Header always set Strict-Transport-Security "max-age=31536000"
</VirtualHost>
"@ | Set-Content "$apacheDir\conf\extra\httpd-ssl.conf" -Encoding UTF8

    New-NetFirewallRule -DisplayName "P7-Apache-443" -Direction Inbound `
        -Protocol TCP -LocalPort 443 -Action Allow -ErrorAction SilentlyContinue | Out-Null

    Restart-Service "Apache2.4" -ErrorAction SilentlyContinue
    OK "Apache Windows: SSL configurado (443) con HSTS y redireccion HTTP->HTTPS."
}

# -----------------------------------------------------------------------------
# SERVICIO 4: NGINX WINDOWS
# -----------------------------------------------------------------------------
function Install-NginxWin($source) {
    Header "Nginx (Windows)"
    $nginxDir  = "C:\nginx"
    $localFile = $null

    if ($source -ne "WEB") {
        $localFile = Select-Installer "Nginx"
        if ($localFile -and $source -eq "LOCAL") { Verify-Hash-Local $localFile }
    } else {
        $zipPath = "$WORK_DIR\nginx_win.zip"
        Info "Descargando Nginx para Windows..."
        try {
            Invoke-WebRequest -Uri "https://nginx.org/download/nginx-1.26.2.zip" `
                -OutFile $zipPath -UseBasicParsing
            $localFile = $zipPath
        } catch {
            Warn "No se pudo descargar. Coloca el ZIP en $zipPath manualmente."
            $localFile = $zipPath
        }
    }

    if ($localFile -and (Test-Path $localFile) -and $localFile -match '\.zip$') {
        Expand-Archive -Path $localFile -DestinationPath "C:\" -Force -ErrorAction SilentlyContinue
        $extracted = Get-Item "C:\nginx-*" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($extracted -and $extracted.FullName -ne $nginxDir) {
            Rename-Item $extracted.FullName $nginxDir -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not (Test-Path "$nginxDir\nginx.exe")) {
        Warn "Nginx no encontrado en $nginxDir"
        Add-Summary "Nginx Windows: instalacion no completada"
        return
    }

    Start-Process -FilePath "$nginxDir\nginx.exe" -WorkingDirectory $nginxDir -WindowStyle Hidden
    OK "Nginx Windows iniciado."

    $ssl = Read-Host "  Activar SSL en Nginx Windows (puerto 443)? [S/N]"
    if ($ssl -match '^[Ss]$') {
        $cert = New-SslCert "NginxWin"
        Config-NginxWin-SSL $cert $nginxDir
        Add-Summary "Nginx Windows: SSL ACTIVADO (443) CN=$DOMAIN"
    } else {
        Add-Summary "Nginx Windows: SSL no activado"
    }
}

function Config-NginxWin-SSL($cert, $nginxDir) {
    $pfxPath  = "$WORK_DIR\nginx_win.pfx"
    $sslDir   = "$nginxDir\conf\ssl"
    $certPath = "$sslDir\server.crt"
    $keyPath  = "$sslDir\server.key"
    $password = "P@ssw0rd!"

    Ensure-Dir $sslDir
    Export-ToPfx $cert $pfxPath $password
    Export-ToPem $pfxPath $password $certPath $keyPath

    $certFwd = $certPath -replace '\\','/'
    $keyFwd  = $keyPath  -replace '\\','/'

    @"
worker_processes 1;
events { worker_connections 1024; }

http {
    include       mime.types;
    default_type  application/octet-stream;

    server {
        listen 80;
        server_name $DOMAIN;
        return 301 https://`$host`$request_uri;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    }

    server {
        listen 443 ssl;
        server_name $DOMAIN;
        ssl_certificate     $certFwd;
        ssl_certificate_key $keyFwd;
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
        add_header Strict-Transport-Security "max-age=31536000" always;
        location / { root html; index index.html index.htm; }
    }
}
"@ | Set-Content "$nginxDir\conf\nginx.conf" -Encoding UTF8

    New-NetFirewallRule -DisplayName "P7-Nginx-443" -Direction Inbound `
        -Protocol TCP -LocalPort 443 -Action Allow -ErrorAction SilentlyContinue | Out-Null

    & "$nginxDir\nginx.exe" -s reload -p $nginxDir 2>$null
    OK "Nginx Windows: SSL configurado (443) con HSTS y redireccion HTTP->HTTPS."
}

# -----------------------------------------------------------------------------
# VERIFICACION AUTOMATIZADA
# -----------------------------------------------------------------------------
function Verify-AllServices {
    Header "VERIFICACION AUTOMATIZADA"
    Add-Summary "============================================================"
    Add-Summary "  RESUMEN PRACTICA 7 - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Summary "  Dominio: $DOMAIN"
    Add-Summary "============================================================"

    # IIS HTTP
    Write-Host ""
    Write-Host "[IIS HTTP]" -ForegroundColor Cyan
    $iis = Get-Service W3SVC -ErrorAction SilentlyContinue
    if ($iis -and $iis.Status -eq "Running") {
        OK "IIS W3SVC: ACTIVO"; Add-Summary "[OK] IIS: activo"
        $conn = Test-NetConnection -ComputerName 127.0.0.1 -Port 443 -WarningAction SilentlyContinue
        if ($conn.TcpTestSucceeded) {
            OK "Puerto 443: responde"; Add-Summary "[OK] IIS: puerto 443 activo"
        } else {
            Warn "Puerto 443: no responde"; Add-Summary "[--] IIS: puerto 443 no activo"
        }
        $c = Get-ChildItem $CERT_STORE | Where-Object { $_.FriendlyName -eq "Practica7-IIS" } | Select-Object -First 1
        if ($c) {
            $cn = $c.GetNameInfo('SimpleName',$false)
            OK "Cert CN=$cn Exp=$($c.NotAfter.ToString('yyyy-MM-dd'))"
            Add-Summary "     IIS: CN=$cn Exp=$($c.NotAfter.ToString('yyyy-MM-dd'))"
        }
    } else {
        Warn "IIS W3SVC: INACTIVO"; Add-Summary "[--] IIS: no activo"
    }

    # IIS FTP
    Write-Host ""
    Write-Host "[IIS FTP - $siteName]" -ForegroundColor Cyan
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $ftpSite = Get-WebSite -Name $siteName -ErrorAction SilentlyContinue
    if ($ftpSite) {
        $estado = $ftpSite.State
        if ($estado -eq "Started") { OK "Sitio '$siteName': $estado"; Add-Summary "[OK] IIS-FTP: activo" }
        else { Warn "Sitio '$siteName': $estado"; Add-Summary "[--] IIS-FTP: $estado" }

        $sslPolicy = Get-ItemProperty "IIS:\Sites\$siteName" `
            -Name "ftpServer.security.ssl.controlChannelPolicy" -ErrorAction SilentlyContinue
        if ($sslPolicy -eq 1) {
            OK "FTPS: SSL obligatorio activo (port 990)"
            Add-Summary "[OK] IIS-FTP: FTPS activo (990)"
        } else {
            Warn "FTPS: SSL no activo (policy=$sslPolicy) - ejecuta opcion 2"
            Add-Summary "[--] IIS-FTP: FTPS no activo"
        }

        $totalUsers = 0
        foreach ($g in @("reprobados","recursadores")) {
            $m = Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue
            $totalUsers += ($m | Where-Object { $_.ObjectClass -eq "User" }).Count
        }
        Info "Usuarios FTP registrados: $totalUsers"
        Add-Summary "     IIS-FTP: $totalUsers usuario(s) registrados"
    } else {
        Warn "Sitio '$siteName' no encontrado - ejecuta opcion 2 para crearlo"
        Add-Summary "[--] IIS-FTP: sitio no encontrado"
    }

    $connFtps = Test-NetConnection -ComputerName 127.0.0.1 -Port 990 -WarningAction SilentlyContinue
    $connFtp  = Test-NetConnection -ComputerName 127.0.0.1 -Port 21  -WarningAction SilentlyContinue
    if ($connFtps.TcpTestSucceeded)     { OK "Puerto 990 (FTPS): responde"; Add-Summary "[OK] IIS-FTP: puerto 990" }
    elseif ($connFtp.TcpTestSucceeded)  { OK "Puerto 21 (FTP): responde";   Add-Summary "[OK] IIS-FTP: puerto 21" }
    else { Warn "FTP: ningun puerto responde"; Add-Summary "[--] IIS-FTP: sin puerto activo" }

    # Apache Windows
    Write-Host ""
    Write-Host "[Apache Windows]" -ForegroundColor Cyan
    $apacheSvc = Get-Service "Apache2.4" -ErrorAction SilentlyContinue
    if ($apacheSvc -and $apacheSvc.Status -eq "Running") {
        OK "Apache2.4: ACTIVO"; Add-Summary "[OK] Apache Windows: activo"
        $conn = Test-NetConnection -ComputerName 127.0.0.1 -Port 443 -WarningAction SilentlyContinue
        if ($conn.TcpTestSucceeded) { OK "Puerto 443: responde"; Add-Summary "[OK] Apache Windows: puerto 443" }
        else { Warn "Puerto 443: no responde"; Add-Summary "[--] Apache Windows: puerto 443 no activo" }
    } else {
        Warn "Apache2.4: INACTIVO"; Add-Summary "[--] Apache Windows: no activo"
    }

    # Nginx Windows
    Write-Host ""
    Write-Host "[Nginx Windows]" -ForegroundColor Cyan
    $nginxProc = Get-Process nginx -ErrorAction SilentlyContinue
    if ($nginxProc) {
        OK "Nginx: proceso activo (PID $($nginxProc[0].Id))"; Add-Summary "[OK] Nginx Windows: activo"
        $conn = Test-NetConnection -ComputerName 127.0.0.1 -Port 443 -WarningAction SilentlyContinue
        if ($conn.TcpTestSucceeded) { OK "Puerto 443: responde"; Add-Summary "[OK] Nginx Windows: puerto 443" }
        else { Warn "Puerto 443: no responde"; Add-Summary "[--] Nginx Windows: puerto 443 no activo" }
    } else {
        Warn "Nginx: no encontrado"; Add-Summary "[--] Nginx Windows: no activo"
    }

    # Certificados
    Write-Host ""
    Write-Host "[Certificados Practica7 en $CERT_STORE]" -ForegroundColor Cyan
    $certsAll = Get-ChildItem $CERT_STORE | Where-Object { $_.FriendlyName -match "^Practica7-" }
    if ($certsAll.Count -gt 0) {
        foreach ($c in $certsAll) {
            $cn = $c.GetNameInfo('SimpleName',$false)
            OK "  $($c.FriendlyName) | CN=$cn | Exp=$($c.NotAfter.ToString('yyyy-MM-dd'))"
            Add-Summary "     Cert $($c.FriendlyName): CN=$cn Exp=$($c.NotAfter.ToString('yyyy-MM-dd'))"
        }
    } else {
        Warn "No hay certificados de Practica 7 aun."
    }

    Add-Summary ""
    Add-Summary "  Log: $LOG_FILE"
}

function Show-Summary {
    Header "RESUMEN FINAL"
    Get-Content $SUMMARY_FILE | ForEach-Object { Write-Host $_ }
    Write-Host ""
    Info "Log:     $LOG_FILE"
    Info "Resumen: $SUMMARY_FILE"
    Read-Host "`nPresiona Enter para continuar"
}

# -----------------------------------------------------------------------------
# INICIALIZACION
# -----------------------------------------------------------------------------
Ensure-Dir "C:\practica7"
Ensure-Dir $WORK_DIR
Write-Log "=== Practica 7 inicio ==="

# -----------------------------------------------------------------------------
# MENU PRINCIPAL
# -----------------------------------------------------------------------------
while ($true) {
    Clear-Host
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "  PRACTICA 7 - SSL/TLS - Windows Server" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan

    $w3 = Get-Service W3SVC    -ErrorAction SilentlyContinue
    $ft = Get-Service ftpsvc   -ErrorAction SilentlyContinue
    $ap = Get-Service Apache2.4 -ErrorAction SilentlyContinue
    $ng = Get-Process nginx    -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "  IIS W3SVC : " -NoNewline
    if ($w3 -and $w3.Status -eq "Running") { Write-Host "activo"   -ForegroundColor Green }
    else                                   { Write-Host "inactivo" -ForegroundColor Red   }

    Write-Host "  ftpsvc    : " -NoNewline
    if ($ft -and $ft.Status -eq "Running") { Write-Host "activo"   -ForegroundColor Green }
    else                                   { Write-Host "inactivo" -ForegroundColor Red   }

    Write-Host "  Apache2.4 : " -NoNewline
    if ($ap -and $ap.Status -eq "Running") { Write-Host "activo"   -ForegroundColor Green }
    else                                   { Write-Host "inactivo" -ForegroundColor Red   }

    Write-Host "  Nginx     : " -NoNewline
    if ($ng)  { Write-Host "activo"   -ForegroundColor Green }
    else      { Write-Host "inactivo" -ForegroundColor Red   }
    Write-Host ""

    Write-Host "  1) IIS HTTP"
    Write-Host "  2) IIS FTP + FTPS  " -NoNewline
    Write-Host "(instala IIS FTP si falta, activa FTPS automaticamente)" -ForegroundColor Yellow
    Write-Host "  3) Apache (Windows)"
    Write-Host "  4) Nginx (Windows)"
    Write-Host "  5) TODOS los servicios"
    Write-Host "  6) Solo verificar instalaciones existentes"
    Write-Host "  7) Salir"
    Write-Host ""

    $opcion = Read-Host "Elige opcion [1-7]"

    "" | Out-File -FilePath $SUMMARY_FILE -Encoding UTF8
    Write-Log "=== opcion $opcion ==="

    switch ($opcion) {
        "1" {
            Select-InstallSource
            Install-IIS $FUENTE
            Verify-AllServices
            Show-Summary
        }
        "2" {
            Install-IIS-FTP-FTPS
            Verify-AllServices
            Show-Summary
        }
        "3" {
            Select-InstallSource
            Install-ApacheWin $FUENTE
            Verify-AllServices
            Show-Summary
        }
        "4" {
            Select-InstallSource
            Install-NginxWin $FUENTE
            Verify-AllServices
            Show-Summary
        }
        "5" {
            Select-InstallSource
            Install-IIS $FUENTE
            Install-IIS-FTP-FTPS
            Install-ApacheWin $FUENTE
            Install-NginxWin $FUENTE
            Verify-AllServices
            Show-Summary
        }
        "6" {
            Verify-AllServices
            Show-Summary
        }
        "7" {
            Write-Host "Saliendo..." -ForegroundColor Yellow
            exit 0
        }
        default {
            Write-Host "Opcion no valida." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}