#Requires -RunAsAdministrator
$ErrorActionPreference = "Continue"  # No detener el script por errores no criticos

# ============================================================
# VARIABLES GLOBALES
# ============================================================
$ftpBaseDir   = "C:\FTP_Base"
$ftpSiteDir   = "C:\FTP_Site"
$localUserDir = "$ftpSiteDir\LocalUser"
$siteName     = "ServidorFTP"

# ============================================================
# FUNCIONES AUXILIARES DE PERMISOS NTFS
# ============================================================

# Establece permisos base (SYSTEM + Admins en control total) y agrega la identidad indicada.
# Rompe la herencia para que solo existan las reglas explicitas.
function Set-NTFSPermissions {
    param(
        [string]$Path,
        [string]$Identity,
        [string]$Rights = "Modify"
    )
    $acl = Get-Acl $Path
    $acl.SetAccessRuleProtection($true, $false)   # Romper herencia

    # SIDs universales (independientes del idioma de Windows)
    $sysSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")    # SYSTEM
    $admSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544") # Administradores

    $inherit = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $none    = [System.Security.AccessControl.PropagationFlags]"None"

    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sysSid, "FullControl", $inherit, $none, "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admSid, "FullControl", $inherit, $none, "Allow")))

    $idRef = if ($Identity -match "^S-1-") {
        New-Object System.Security.Principal.SecurityIdentifier($Identity)
    } else {
        New-Object System.Security.Principal.NTAccount($Identity)
    }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($idRef, $Rights, $inherit, $none, "Allow")))
    Set-Acl -Path $Path -AclObject $acl
}

# Agrega un permiso sin modificar las reglas existentes (sin romper herencia).
function Add-NTFSPermission {
    param(
        [string]$Path,
        [string]$Identity,
        [string]$Rights
    )
    $acl   = Get-Acl $Path
    $inherit = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $none    = [System.Security.AccessControl.PropagationFlags]"None"
    $idRef = if ($Identity -match "^S-1-") {
        New-Object System.Security.Principal.SecurityIdentifier($Identity)
    } else {
        New-Object System.Security.Principal.NTAccount($Identity)
    }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($idRef, $Rights, $inherit, $none, "Allow")))
    Set-Acl -Path $Path -AclObject $acl
}

# Crea un junction point solo si no existe ya.
function New-JunctionIfMissing {
    param([string]$JunctionPath, [string]$TargetPath)
    if (-not (Test-Path $JunctionPath)) {
        cmd /c mklink /J "$JunctionPath" "$TargetPath" | Out-Null
    }
}

# Elimina un junction point (sin borrar el destino).
function Remove-Junction {
    param([string]$JunctionPath)
    if (Test-Path $JunctionPath) {
        cmd /c rd /S /Q "$JunctionPath" | Out-Null
    }
}

# ============================================================
# 1. INSTALAR / CONFIGURAR SERVIDOR FTP
# ============================================================
function Instalar-FTP {
    Clear-Host
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host " Instalacion y Configuracion IIS FTP " -ForegroundColor Cyan
    Write-Host "======================================`n" -ForegroundColor Cyan

    Import-Module ServerManager -ErrorAction SilentlyContinue

    # --- Verificar / instalar caracteristica FTP ---
    $ftpFeature = Get-WindowsFeature Web-Ftp-Server -ErrorAction SilentlyContinue
    if ($ftpFeature -and $ftpFeature.Installed) {
        $reinstall = Read-Host "El servicio FTP ya esta instalado. Deseas reconfigurar? (s/n)"
        if ($reinstall -notmatch "^[sS]$") {
            Write-Host "Omitiendo instalacion..." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            return
        }
    } else {
        Write-Host "Instalando IIS y FTP. Por favor espera..." -ForegroundColor Yellow
        Install-WindowsFeature Web-Server, Web-Ftp-Server, Web-Ftp-Service, Web-Mgmt-Console -IncludeManagementTools | Out-Null
        Write-Host "Instalacion completada." -ForegroundColor Green
    }

    Import-Module WebAdministration -ErrorAction SilentlyContinue

    # --- Crear grupos locales ---
    foreach ($grupo in @("reprobados", "recursadores")) {
        if (-not (Get-LocalGroup -Name $grupo -ErrorAction SilentlyContinue)) {
            New-LocalGroup -Name $grupo -Description "Grupo FTP $grupo" | Out-Null
            Write-Host "Grupo '$grupo' creado." -ForegroundColor Green
        } else {
            Write-Host "Grupo '$grupo' ya existe." -ForegroundColor DarkGray
        }
    }

    # --- Estructura base de directorios ---
    Write-Host "Configurando estructura de directorios..." -ForegroundColor Yellow
    foreach ($dir in @("$ftpBaseDir\general", "$ftpBaseDir\reprobados", "$ftpBaseDir\recursadores")) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    # Permisos carpeta /general:
    # - Everyone (S-1-1-0)           -> ReadAndExecute SOLAMENTE (incluye anonimos)
    # - Authenticated Users (S-1-5-11) -> Modify (usuarios logueados pueden escribir)
    # - Everyone DENY Write/Modify/Delete -> bloquea escritura anonima a nivel NTFS
    # NTFS aplica Deny antes que Allow, por lo que el anonimo jamas podra escribir
    # aunque IIS le asigne permisos FTP de escritura por error de configuracion.
    Set-NTFSPermissions -Path "$ftpBaseDir\general" -Identity "S-1-1-0" -Rights "ReadAndExecute"
    Add-NTFSPermission  -Path "$ftpBaseDir\general" -Identity "S-1-5-11" -Rights "Modify"

    # Deny explicito de escritura a Everyone en /general
    # NTFS procesa Deny con mayor prioridad que Allow.
    # Authenticated Users hereda Modify (Allow), que SUPERA el Deny de Everyone
    # porque las reglas Allow de usuario especifico tienen precedencia sobre Deny de grupo.
    # El anonimo (no autenticado) solo tiene Allow ReadAndExecute + Deny Write = solo lectura.
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

    # Permisos carpetas de grupo: solo miembros del grupo tienen Modify
    Set-NTFSPermissions -Path "$ftpBaseDir\reprobados"  -Identity "reprobados"  -Rights "Modify"
    Set-NTFSPermissions -Path "$ftpBaseDir\recursadores" -Identity "recursadores" -Rights "Modify"

    # --- Eliminar sitios previos si existen ---
    foreach ($s in @($siteName, "Default FTP Site")) {
        if (Get-WebSite -Name $s -ErrorAction SilentlyContinue) {
            Remove-WebSite -Name $s -ErrorAction SilentlyContinue
        }
    }

    # --- Crear estructura del sitio IIS ---
    New-Item -Path $ftpSiteDir   -ItemType Directory -Force | Out-Null
    New-Item -Path $localUserDir -ItemType Directory -Force | Out-Null

    # --- Crear sitio FTP ---
    New-WebFtpSite -Name $siteName -Port 21 -PhysicalPath $ftpSiteDir -Force | Out-Null

    # Modo de aislamiento: 3 = IsolateAllDirectories (LocalUser/<usuario>)
    # Valor 2 = IsolateRootDirectoryOnly (usamos 3 para aislamiento completo)
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.userIsolation.mode" -Value 3

    # SSL: deshabilitado (0 = SslAllow sin certificado = sin SSL obligatorio)
    # Valor 0 = SslAllow, 1 = SslRequire, 2 = ClientCertRequire, 3 = NoClientCert
    # Usamos 0 para que NO exija SSL - esto corrige el error "534 Policy requires SSL"
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.security.ssl.controlChannelPolicy" -Value 0
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.security.ssl.dataChannelPolicy"    -Value 0
    # Limpiar certificado SSL para que no intente forzar TLS
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.security.ssl.serverCertHash"       -Value ""
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.security.ssl.serverCertStoreName"  -Value "MY"

    # Autenticacion: basica habilitada, anonima habilitada
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.security.authentication.basicAuthentication.enabled"     -Value $true
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.security.authentication.anonymousAuthentication.enabled" -Value $true

    # --- Reglas de autorizacion FTP ---
    # Limpiar reglas previas del sitio
    Clear-WebConfiguration -Filter "/system.ftpServer/security/authorization" -PSPath "IIS:\" -Location $siteName -ErrorAction SilentlyContinue

    # ORDEN IMPORTA: IIS evalua las reglas de arriba hacia abajo.
    # 1) Anonimo (?): solo lectura - debe ir ANTES que el wildcard (*)
    Add-WebConfiguration -Filter "/system.ftpServer/security/authorization" `
        -PSPath "IIS:\" -Location $siteName `
        -Value @{accessType="Allow"; users="?"; permissions="Read"}

    # 2) Usuarios autenticados (*): lectura y escritura
    Add-WebConfiguration -Filter "/system.ftpServer/security/authorization" `
        -PSPath "IIS:\" -Location $siteName `
        -Value @{accessType="Allow"; users="*"; permissions="Read,Write"}

    # --- Directorio del usuario anonimo ---
    # Con aislamiento modo 3, el anonimo usa LocalUser\Public
    $anonDir = "$localUserDir\Public"
    New-Item -Path $anonDir -ItemType Directory -Force | Out-Null

    # El anonimo solo ve /general (junction)
    New-JunctionIfMissing -JunctionPath "$anonDir\general" -TargetPath "$ftpBaseDir\general"

    # Permisos NTFS carpeta Public: Everyone solo lectura (doble proteccion vs escritura anonima)
    Set-NTFSPermissions -Path $anonDir -Identity "S-1-1-0" -Rights "ReadAndExecute"

    # Nota: el Deny de escritura a Everyone aplicado arriba sobre $ftpBaseDir\general
    # ya cubre al anonimo de IIS (IUSR, IIS_IUSRS, etc.) sin importar que cuenta use.
    # Authenticated Users tiene Allow Modify que tiene precedencia sobre el Deny de grupo.

    # Reiniciar el servicio FTP para aplicar cambios
    # Start/Stop-WebSite falla en sitios FTP con error 0x800710D8, se usa ftpsvc
    try {
        Restart-Service -Name "ftpsvc" -Force -ErrorAction Stop
        Write-Host "Servicio FTP reiniciado correctamente." -ForegroundColor Green
    } catch {
        Write-Host "Aviso: No se pudo reiniciar ftpsvc. Reinicialo manualmente." -ForegroundColor Yellow
    }

    Write-Host "`nInstalacion y configuracion base finalizada." -ForegroundColor Green
    Write-Host "Puerto 21 abierto. Recuerda habilitar el puerto en el Firewall si es necesario." -ForegroundColor Yellow

    # Abrir puerto 21 en el Firewall de Windows (idempotente)
    $fwRule = Get-NetFirewallRule -DisplayName "FTP Server (TCP-In)" -ErrorAction SilentlyContinue
    if (-not $fwRule) {
        New-NetFirewallRule -DisplayName "FTP Server (TCP-In)" -Direction Inbound -Protocol TCP -LocalPort 21 -Action Allow | Out-Null
        Write-Host "Regla de firewall creada para el puerto 21." -ForegroundColor Green
    }

    Read-Host "`nPresiona Enter para continuar"
}

# ============================================================
# 2. GESTIONAR USUARIOS
# ============================================================
function Gestionar-Usuarios {
    Clear-Host
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host " Gestion de Usuarios FTP             " -ForegroundColor Cyan
    Write-Host "======================================`n" -ForegroundColor Cyan

    if (-not (Test-Path $ftpSiteDir)) {
        Write-Host "Error: Primero instala el servidor FTP (Opcion 1)." -ForegroundColor Red
        Read-Host "Presiona Enter para continuar"
        return
    }

    Import-Module WebAdministration -ErrorAction SilentlyContinue

    $numUsers = 0
    do {
        $inputStr = Read-Host "Cantidad de usuarios a procesar (numero entero positivo)"
        [int]::TryParse($inputStr.Trim(), [ref]$numUsers) | Out-Null
        if ($numUsers -le 0) { Write-Host "Ingresa un numero valido mayor a 0." -ForegroundColor Yellow }
    } while ($numUsers -le 0)

    for ($i = 1; $i -le $numUsers; $i++) {
        Write-Host "`n--- Usuario $i / $numUsers ---" -ForegroundColor White

        # Nombre de usuario
        $username = ""
        do {
            $username = (Read-Host "  Nombre de usuario").Trim().ToLower()
            if ($username -eq "") { Write-Host "  El nombre no puede estar vacio." -ForegroundColor Yellow }
        } while ($username -eq "")

        # Contrasena con confirmacion
        Write-Host "  [!] Usa contrasena compleja (ej: Admin.123!)" -ForegroundColor Yellow
        $securePass = $null
        do {
            $pass1 = Read-Host "  Contrasena" -AsSecureString
            $pass2 = Read-Host "  Confirmar contrasena" -AsSecureString

            $bstr1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass1)
            $bstr2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass2)
            $str1  = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr1)
            $str2  = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr2)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)

            if ($str1 -eq "" ) { Write-Host "  La contrasena no puede estar vacia." -ForegroundColor Red }
            elseif ($str1 -ne $str2) { Write-Host "  Las contrasenas no coinciden." -ForegroundColor Red }
            else { $securePass = $pass1 }
        } while ($null -eq $securePass)

        # Seleccion de grupo
        $grupo = ""
        do {
            Write-Host "  Grupo: [1] reprobados  [2] recursadores"
            $grupoSel = Read-Host "  Seleccion (1/2)"
            if ($grupoSel -eq "1") { $grupo = "reprobados" }
            elseif ($grupoSel -eq "2") { $grupo = "recursadores" }
            else { Write-Host "  Opcion invalida." -ForegroundColor Yellow }
        } while ($grupo -eq "")

        # ---- Procesar usuario ----
        $userObj = Get-LocalUser -Name $username -ErrorAction SilentlyContinue

        if ($userObj) {
            # Usuario EXISTENTE: actualizar contrasena y/o grupo
            try {
                Set-LocalUser -Name $username -Password $securePass
            } catch {
                Write-Host "  [X] Error al actualizar contrasena: $_" -ForegroundColor Red
                continue
            }

            # Determinar grupo actual
            $oldGroup = $null
            foreach ($g in @("reprobados", "recursadores")) {
                if (Get-LocalGroupMember -Group $g -Member $username -ErrorAction SilentlyContinue) {
                    $oldGroup = $g
                    break
                }
            }

            if ($oldGroup -ne $grupo) {
                # Cambiar de grupo
                if ($oldGroup) {
                    Remove-LocalGroupMember -Group $oldGroup -Member $username -ErrorAction SilentlyContinue
                }
                Add-LocalGroupMember -Group $grupo -Member $username

                Write-Host "  Grupo cambiado: '$oldGroup' -> '$grupo'" -ForegroundColor Green

                # Actualizar junction del grupo en el directorio del usuario
                $uDir = "$localUserDir\$username"
                if ($oldGroup) { Remove-Junction -JunctionPath "$uDir\$oldGroup" }
                New-JunctionIfMissing -JunctionPath "$uDir\$grupo" -TargetPath "$ftpBaseDir\$grupo"

                # CRITICO: actualizar permisos NTFS individuales del usuario en las carpetas de grupo.
                # Se quita el permiso del grupo anterior y se agrega en el nuevo.
                # Sin esto IIS FTP devuelve Error 550 al intentar listar la carpeta del grupo.
                if ($oldGroup) {
                    try {
                        $aclOld = Get-Acl "$ftpBaseDir\$oldGroup"
                        $idOld  = New-Object System.Security.Principal.NTAccount($username)
                        $aclOld.PurgeAccessRules($idOld)
                        Set-Acl -Path "$ftpBaseDir\$oldGroup" -AclObject $aclOld
                    } catch {
                        Write-Host "  Aviso: no se pudo limpiar permisos del grupo anterior." -ForegroundColor Yellow
                    }
                }
                Add-NTFSPermission -Path "$ftpBaseDir\$grupo" -Identity $username -Rights "Modify"
            } else {
                Write-Host "  Contrasena actualizada. Grupo sin cambios ('$grupo')." -ForegroundColor Green
            }

        } else {
            # Usuario NUEVO
            try {
                New-LocalUser -Name $username -Password $securePass -PasswordNeverExpires -ErrorAction Stop | Out-Null
            } catch {
                Write-Host "  [X] Error al crear usuario '$username': $_" -ForegroundColor Red
                Write-Host "       Recuerda: mayusculas, minusculas, numeros y simbolos." -ForegroundColor Yellow
                continue
            }

            Add-LocalGroupMember -Group $grupo -Member $username
            Write-Host "  Usuario '$username' creado y asignado al grupo '$grupo'." -ForegroundColor Green

            # ---- Estructura de directorios del usuario ----
            # Con aislamiento modo 3:  FTP_Site\LocalUser\<usuario>\  es la raiz FTP del usuario
            # Dentro se crean las carpetas/junctions visibles al conectarse:
            #   <usuario>\general      -> junction a FTP_Base\general
            #   <usuario>\<grupo>      -> junction a FTP_Base\<grupo>
            #   <usuario>\<username>   -> carpeta personal propia

            $uDir = "$localUserDir\$username"
            New-Item -Path $uDir -ItemType Directory -Force | Out-Null

            # Carpeta personal (mismo nombre que el usuario)
            $personalDir = "$uDir\$username"
            New-Item -Path $personalDir -ItemType Directory -Force | Out-Null
            Set-NTFSPermissions -Path $personalDir -Identity $username -Rights "Modify"

            # Junctions visibles en la raiz FTP del usuario
            New-JunctionIfMissing -JunctionPath "$uDir\general" -TargetPath "$ftpBaseDir\general"
            New-JunctionIfMissing -JunctionPath "$uDir\$grupo"  -TargetPath "$ftpBaseDir\$grupo"

            # Permisos en la carpeta raiz del usuario
            Set-NTFSPermissions -Path $uDir -Identity $username -Rights "ReadAndExecute"

            # CRITICO: agregar permiso NTFS individual del usuario en la carpeta del grupo.
            # IIS FTP verifica permisos sobre el target real de la junction con el token
            # del usuario, no con el token del grupo. Sin esto -> Error 550.
            Add-NTFSPermission -Path "$ftpBaseDir\$grupo" -Identity $username -Rights "Modify"
        }
    }

    Write-Host "`nGestion de usuarios finalizada." -ForegroundColor Green
    Read-Host "Presiona Enter para continuar"
}

# ============================================================
# 3. LISTAR USUARIOS Y GRUPOS
# ============================================================
function Listar-Usuarios {
    Clear-Host
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host " Usuarios FTP Registrados             " -ForegroundColor Cyan
    Write-Host "======================================`n" -ForegroundColor Cyan

    Write-Host ("{0,-22} | {1,-15}" -f "USUARIO", "GRUPO") -ForegroundColor White
    Write-Host ("-" * 42)

    $found = $false
    foreach ($grp in @("reprobados", "recursadores")) {
        $members = Get-LocalGroupMember -Group $grp -ErrorAction SilentlyContinue
        foreach ($member in $members) {
            if ($member.ObjectClass -eq "User") {
                $name = $member.Name -replace "^$env:COMPUTERNAME\\", ""
                Write-Host ("{0,-22} | {1,-15}" -f $name, $grp)
                $found = $true
            }
        }
    }

    if (-not $found) {
        Write-Host "No hay usuarios registrados en los grupos FTP." -ForegroundColor Yellow
    }

    Write-Host ""
    Read-Host "Presiona Enter para regresar al menu"
}

# ============================================================
# 4. ELIMINAR USUARIO FTP
# ============================================================
function Eliminar-Usuario {
    Clear-Host
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host " Eliminar Usuario FTP                 " -ForegroundColor Cyan
    Write-Host "======================================`n" -ForegroundColor Cyan

    $username = (Read-Host "Nombre de usuario a eliminar").Trim().ToLower()
    if ($username -eq "") { Write-Host "Nombre vacio. Cancelando." -ForegroundColor Yellow; Read-Host; return }

    $userObj = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
    if (-not $userObj) {
        Write-Host "El usuario '$username' no existe." -ForegroundColor Red
        Read-Host "Presiona Enter para continuar"
        return
    }

    $confirm = Read-Host "Confirmar eliminacion de '$username' (s/n)"
    if ($confirm -notmatch "^[sS]$") { Write-Host "Operacion cancelada." -ForegroundColor Yellow; Read-Host; return }

    # Remover de grupos
    foreach ($g in @("reprobados", "recursadores")) {
        Remove-LocalGroupMember -Group $g -Member $username -ErrorAction SilentlyContinue
    }

    # Eliminar directorio FTP del usuario
    $uDir = "$localUserDir\$username"
    if (Test-Path $uDir) {
        # Primero eliminar junctions manualmente para no borrar el contenido de los targets
        foreach ($j in Get-ChildItem -Path $uDir -Attributes ReparsePoint -ErrorAction SilentlyContinue) {
            cmd /c rd "$($j.FullName)" | Out-Null
        }
        Remove-Item -Path $uDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Eliminar cuenta local
    Remove-LocalUser -Name $username
    Write-Host "Usuario '$username' eliminado correctamente." -ForegroundColor Green
    Read-Host "Presiona Enter para continuar"
}

# ============================================================
# 5. REPARAR SSL (Fix error 534 - Policy requires SSL)
# ============================================================
function Reparar-SSL {
    Clear-Host
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host " Reparar SSL - Fix error 534          " -ForegroundColor Cyan
    Write-Host "======================================`n" -ForegroundColor Cyan

    Import-Module WebAdministration -ErrorAction SilentlyContinue

    $site = Get-WebSite -Name $siteName -ErrorAction SilentlyContinue
    if (-not $site) {
        Write-Host "El sitio '$siteName' no existe. Instala primero el servidor FTP." -ForegroundColor Red
        Read-Host "Presiona Enter para continuar"
        return
    }

    Write-Host "Deshabilitando SSL obligatorio en el sitio '$siteName'..." -ForegroundColor Yellow

    # 0 = SslAllow (no forzar SSL), resuelve error "534 Policy requires SSL"
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.security.ssl.controlChannelPolicy" -Value 0
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.security.ssl.dataChannelPolicy"    -Value 0
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.security.ssl.serverCertHash"       -Value ""
    Set-ItemProperty "IIS:\Sites\$siteName" -Name "ftpServer.security.ssl.serverCertStoreName"  -Value "MY"

    # Reiniciar el servicio FTP para aplicar cambios
    # Start/Stop-WebSite falla en sitios FTP con error 0x800710D8, se usa ftpsvc
    try {
        Restart-Service -Name "ftpsvc" -Force -ErrorAction Stop
        Write-Host "Servicio FTP reiniciado correctamente." -ForegroundColor Green
    } catch {
        Write-Host "Aviso: No se pudo reiniciar ftpsvc. Reinicialo manualmente si es necesario." -ForegroundColor Yellow
    }

    Write-Host "SSL deshabilitado. El error 534 deberia estar resuelto." -ForegroundColor Green
    Write-Host "Conectate con: ftp <IP-del-servidor>" -ForegroundColor Cyan
    Read-Host "Presiona Enter para continuar"
}


# ============================================================
# 6. REPARAR PERMISOS DE USUARIOS EXISTENTES (Fix error 550)
# ============================================================
function Reparar-Permisos {
    Clear-Host
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host " Reparar Permisos - Fix error 550     " -ForegroundColor Cyan
    Write-Host "======================================`n" -ForegroundColor Cyan

    Write-Host "Recorriendo usuarios FTP registrados y reparando permisos NTFS..." -ForegroundColor Yellow
    Write-Host ""

    # Reaplicar Deny de escritura a Everyone en /general (proteccion anonimo)
    Write-Host "  Aplicando proteccion de solo lectura en /general para anonimos..." -ForegroundColor Yellow
    try {
        $inheritFlags  = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
        $propFlags     = [System.Security.AccessControl.PropagationFlags]"None"
        $everyoneSid   = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
        $denyWriteRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $everyoneSid,
            [System.Security.AccessControl.FileSystemRights]"Write,AppendData,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership,CreateFiles,CreateDirectories",
            $inheritFlags, $propFlags, "Deny"
        )
        $aclGen = Get-Acl "$ftpBaseDir\general"
        # Eliminar reglas Deny previas de Everyone para no duplicar
        $aclGen.Access | Where-Object {
            $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "S-1-1-0" -and
            $_.AccessControlType -eq "Deny"
        } | ForEach-Object { $aclGen.RemoveAccessRule($_) | Out-Null }
        $aclGen.AddAccessRule($denyWriteRule)
        Set-Acl -Path "$ftpBaseDir\general" -AclObject $aclGen
        Write-Host "    OK - Anonimo: solo lectura en /general" -ForegroundColor Green
    } catch {
        Write-Host "    Aviso: $_" -ForegroundColor Yellow
    }

    $grupos = @("reprobados", "recursadores")
    $reparados = 0

    foreach ($grp in $grupos) {
        $members = Get-LocalGroupMember -Group $grp -ErrorAction SilentlyContinue
        foreach ($member in $members) {
            if ($member.ObjectClass -ne "User") { continue }
            $username = $member.Name -replace "^$env:COMPUTERNAME\\", ""
            $uDir = "$localUserDir\$username"

            Write-Host "  Usuario: $username (grupo: $grp)" -ForegroundColor White

            # 1. Asegurar que la carpeta raiz del usuario existe y tiene permisos
            if (-not (Test-Path $uDir)) {
                New-Item -Path $uDir -ItemType Directory -Force | Out-Null
            }
            Set-NTFSPermissions -Path $uDir -Identity $username -Rights "ReadAndExecute"

            # 2. Carpeta personal
            $personalDir = "$uDir\$username"
            if (-not (Test-Path $personalDir)) {
                New-Item -Path $personalDir -ItemType Directory -Force | Out-Null
            }
            Set-NTFSPermissions -Path $personalDir -Identity $username -Rights "Modify"

            # 3. Junction a general
            New-JunctionIfMissing -JunctionPath "$uDir\general" -TargetPath "$ftpBaseDir\general"

            # 4. Junction al grupo correcto (eliminar junction del grupo contrario si existe)
            $otroGrupo = if ($grp -eq "reprobados") { "recursadores" } else { "reprobados" }
            Remove-Junction -JunctionPath "$uDir\$otroGrupo"
            New-JunctionIfMissing -JunctionPath "$uDir\$grp" -TargetPath "$ftpBaseDir\$grp"

            # 5. CRITICO: permiso NTFS individual en la carpeta del grupo correcto
            Add-NTFSPermission -Path "$ftpBaseDir\$grp" -Identity $username -Rights "Modify"

            # 6. Limpiar permisos del grupo contrario (si los tenia por cambio previo)
            try {
                $aclOtro = Get-Acl "$ftpBaseDir\$otroGrupo"
                $idRef   = New-Object System.Security.Principal.NTAccount($username)
                $aclOtro.PurgeAccessRules($idRef)
                Set-Acl -Path "$ftpBaseDir\$otroGrupo" -AclObject $aclOtro
            } catch {}

            Write-Host "    OK" -ForegroundColor Green
            $reparados++
        }
    }

    Write-Host ""
    if ($reparados -eq 0) {
        Write-Host "No se encontraron usuarios FTP registrados." -ForegroundColor Yellow
    } else {
        Write-Host "$reparados usuario(s) reparado(s) correctamente." -ForegroundColor Green
        Write-Host "El error 550 al entrar a carpetas de grupo deberia estar resuelto." -ForegroundColor Cyan
    }
    Read-Host "`nPresiona Enter para continuar"
}

# ============================================================
# BUCLE PRINCIPAL
# ============================================================
# La directiva #Requires -RunAsAdministrator ya valida esto,
# pero mantenemos el mensaje informativo por claridad.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Host "CRITICO: Debes ejecutar PowerShell como Administrador." -ForegroundColor Red
    Start-Sleep -Seconds 5
    exit 1
}

while ($true) {
    Clear-Host
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "     ADMINISTRACION SERVIDOR FTP      " -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan

    # Estado del servicio
    $ftpFeature = Get-WindowsFeature Web-Ftp-Server -ErrorAction SilentlyContinue
    if ($ftpFeature -and $ftpFeature.Installed) {
        Write-Host "Estado FTP: " -NoNewline; Write-Host "Instalado" -ForegroundColor Green
    } else {
        Write-Host "Estado FTP: " -NoNewline; Write-Host "No Instalado" -ForegroundColor Red
    }

    # Estado del sitio IIS
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $site = Get-WebSite -Name $siteName -ErrorAction SilentlyContinue
    if ($site) {
        Write-Host "Sitio IIS:  " -NoNewline; Write-Host "$($site.State)" -ForegroundColor $(if ($site.State -eq "Started") {"Green"} else {"Yellow"})
    } else {
        Write-Host "Sitio IIS:  " -NoNewline; Write-Host "No configurado" -ForegroundColor DarkGray
    }

    Write-Host "`n  1) Instalar / Configurar servidor FTP"
    Write-Host "  2) Gestionar Usuarios (crear / cambiar grupo / actualizar contrasena)"
    Write-Host "  3) Listar Usuarios y Grupos"
    Write-Host "  4) Eliminar Usuario FTP"
    Write-Host "  5) Reparar SSL (Fix error 534 - Policy requires SSL)" -ForegroundColor Yellow
    Write-Host "  6) Reparar Permisos usuarios existentes (Fix error 550)" -ForegroundColor Yellow
    Write-Host "  7) Salir`n"

    $opcion = Read-Host "Elige una opcion [1-7]"

    switch ($opcion) {
        "1" { Instalar-FTP }
        "2" { Gestionar-Usuarios }
        "3" { Listar-Usuarios }
        "4" { Eliminar-Usuario }
        "5" { Reparar-SSL }
        "6" { Reparar-Permisos }
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