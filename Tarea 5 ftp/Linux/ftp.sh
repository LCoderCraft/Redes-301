#!/bin/bash

set -e

# ══════════════════════════════════════════════════
# COLORES
# ══════════════════════════════════════════════════
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

# ══════════════════════════════════════════════════
# VERIFICAR ROOT
# ══════════════════════════════════════════════════
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: Ejecuta este script como root (ej. sudo bash $0)${NC}"
    exit 1
fi

# ══════════════════════════════════════════════════
# VARIABLES GLOBALES
# ══════════════════════════════════════════════════
FTP_ROOT="/srv/ftp"
GENERAL_DIR="$FTP_ROOT/general"
VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
VSFTPD_USER_LIST="/etc/vsftpd/user_list"
VSFTPD_CHROOT_LIST="/etc/vsftpd/chroot_list"
VALID_GROUPS=("reprobados" "recursadores")
VSFTPD_USERCONF="/etc/vsftpd/users"
VIRTUAL_ROOT="/srv/ftp/virtual"
ANON_ROOT="/var/ftp"

clear

# ══════════════════════════════════════════════════
# UTILIDADES
# ══════════════════════════════════════════════════

detener_vsftpd() {
    systemctl is-active --quiet vsftpd 2>/dev/null && \
        systemctl stop vsftpd 2>/dev/null || true
    sleep 1
}

# Desmontar sin usar fuser (para no matar SSH)
desmontar_seguro() {
    local punto="$1"
    [[ ! -d "$punto" ]] && return 0
    if mountpoint -q "$punto" 2>/dev/null; then
        # Intentar umount normal
        if ! umount "$punto" 2>/dev/null; then
            # Si falla, lazy umount (desvincula sin matar procesos)
            umount -l "$punto" 2>/dev/null || true
        fi
        sleep 0.3
    fi
}

limpiar_virtual_usuario() {
    local username="$1"
    local vroot="$VIRTUAL_ROOT/$username"
    [[ ! -d "$vroot" ]] && return 0

    # Desmontar en orden inverso (hijos antes que padres)
    while IFS= read -r punto; do
        [[ -n "$punto" ]] && desmontar_seguro "$punto"
    done < <(grep " $vroot/" /proc/mounts 2>/dev/null | awk '{print $2}' | sort -r)

    # Limpiar fstab
    sed -i "\|$vroot/|d" /etc/fstab
    systemctl daemon-reload

    # Eliminar carpeta
    rm -rf "$vroot"
}

reconstruir_virtual_usuario() {
    local username="$1"
    local grupo="$2"
    local vroot="$VIRTUAL_ROOT/$username"

    mkdir -p "$FTP_ROOT/$grupo"
    chown root:"$grupo" "$FTP_ROOT/$grupo"
    chmod 775 "$FTP_ROOT/$grupo"

    mkdir -p "$vroot"
    chown root:root "$vroot"
    chmod 755 "$vroot"

    mkdir -p "$vroot/general"
    chown root:ftp "$vroot/general"

    mkdir -p "$vroot/$grupo"
    chown root:"$grupo" "$vroot/$grupo"

    mkdir -p "$vroot/$username"
    chown "$username":"$grupo" "$vroot/$username"
    chmod 770 "$vroot/$username"

    grep -qF "$vroot/general" /etc/fstab || \
        echo "$GENERAL_DIR $vroot/general none bind 0 0" >> /etc/fstab
    grep -qF "$vroot/$grupo" /etc/fstab || \
        echo "$FTP_ROOT/$grupo $vroot/$grupo none bind 0 0" >> /etc/fstab

    systemctl daemon-reload
    mountpoint -q "$vroot/general" 2>/dev/null || mount --bind "$GENERAL_DIR" "$vroot/general"
    mountpoint -q "$vroot/$grupo"  2>/dev/null || mount --bind "$FTP_ROOT/$grupo" "$vroot/$grupo"
    chmod 775 "$vroot/general"
    chmod 775 "$vroot/$grupo"
}

limpiar_anonimo() {
    for dir in "$ANON_ROOT"/*/; do
        [[ ! -d "$dir" ]] && continue
        local dirname
        dirname=$(basename "$dir")
        if [[ "$dirname" != "general" ]]; then
            desmontar_seguro "$dir"
            rm -rf "$dir"
        fi
    done
    mkdir -p "$ANON_ROOT/general"
    chown root:root "$ANON_ROOT"
    chmod 755 "$ANON_ROOT"
    grep -qF "$ANON_ROOT/general" /etc/fstab || \
        echo "$GENERAL_DIR $ANON_ROOT/general none bind 0 0" >> /etc/fstab
    systemctl daemon-reload
    mountpoint -q "$ANON_ROOT/general" 2>/dev/null || \
        mount --bind "$GENERAL_DIR" "$ANON_ROOT/general" 2>/dev/null || true
    chown ftp:ftp "$ANON_ROOT/general"
    chmod 755 "$ANON_ROOT/general"
}

# ══════════════════════════════════════════════════
# OPCIÓN 1: Instalar y configurar vsftpd
# ══════════════════════════════════════════════════
instalar_ftp() {
    clear
    echo -e "${CYAN}${BOLD}══════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD} Instalación y Configuración de vsftpd${NC}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════${NC}\n"

    if rpm -q vsftpd &>/dev/null; then
        read -rp "vsftpd ya está instalado. ¿Reinstalar? (s/n): " REINSTALAR
        if [[ "${REINSTALAR,,}" == "s" ]]; then
            echo "Reinstalando vsftpd..."
            dnf reinstall -yq vsftpd > /dev/null 2>&1 || { echo -e "${RED}Error al reinstalar.${NC}"; exit 1; }
            echo "Reinstalación completada."
        else
            echo "Omitiendo."
        fi
    else
        echo "Instalando vsftpd..."
        dnf install -yq vsftpd > /dev/null 2>&1 || { echo -e "${RED}Error al instalar.${NC}"; exit 1; }
        echo "Instalación completada."
    fi

    systemctl enable vsftpd --quiet
    systemctl is-active --quiet vsftpd || systemctl start vsftpd

    if systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-service=ftp &>/dev/null || true
        firewall-cmd --permanent --add-port=21/tcp &>/dev/null || true
        firewall-cmd --permanent --add-port=40000-40100/tcp &>/dev/null || true
        firewall-cmd --reload &>/dev/null || true
        echo "Firewall configurado."
    fi

    if command -v getenforce &>/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
        setsebool -P ftpd_full_access 1 &>/dev/null || true
        setsebool -P allow_ftpd_full_access 1 &>/dev/null || true
        echo "SELinux configurado."
    fi

    for grupo in "${VALID_GROUPS[@]}"; do
        getent group "$grupo" &>/dev/null || { groupadd "$grupo"; echo "Grupo '$grupo' creado."; }
    done

    mkdir -p "$FTP_ROOT" && chown root:root "$FTP_ROOT" && chmod 755 "$FTP_ROOT"
    mkdir -p "$GENERAL_DIR" && chown root:ftp "$GENERAL_DIR" && chmod 775 "$GENERAL_DIR"
    for grupo in "${VALID_GROUPS[@]}"; do
        mkdir -p "$FTP_ROOT/$grupo"
        chown root:"$grupo" "$FTP_ROOT/$grupo"
        chmod 775 "$FTP_ROOT/$grupo"
    done
    mkdir -p "$VIRTUAL_ROOT" && chown root:root "$VIRTUAL_ROOT" && chmod 755 "$VIRTUAL_ROOT"

    detener_vsftpd
    limpiar_anonimo

    [[ ! -f "${VSFTPD_CONF}.bak" ]] && cp "$VSFTPD_CONF" "${VSFTPD_CONF}.bak"
    mkdir -p "$VSFTPD_USERCONF"

    cat > "$VSFTPD_CONF" << EOF
listen=YES
listen_ipv6=NO
background=YES
nopriv_user=nobody
anonymous_enable=YES
anon_root=/var/ftp
no_anon_password=YES
anon_upload_enable=NO
anon_mkdir_write_enable=NO
anon_other_write_enable=NO
local_enable=YES
write_enable=YES
local_umask=002
pam_service_name=vsftpd
chroot_local_user=YES
chroot_list_enable=NO
allow_writeable_chroot=YES
user_config_dir=$VSFTPD_USERCONF
userlist_enable=YES
userlist_file=/etc/vsftpd/user_list
userlist_deny=NO
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
xferlog_enable=YES
xferlog_file=/var/log/vsftpd.log
xferlog_std_format=YES
log_ftp_protocol=NO
ftpd_banner=Bienvenido al servidor FTP
EOF

    echo "anonymous" > "$VSFTPD_USER_LIST"
    touch "$VSFTPD_CHROOT_LIST"
    grep -q "/sbin/nologin" /etc/shells || echo "/sbin/nologin" >> /etc/shells

    systemctl restart vsftpd
    echo -e "\n${GREEN}Instalación y configuración finalizada.${NC}"
    echo ""; read -rp "Presiona Enter para continuar..."
}

# ══════════════════════════════════════════════════
# OPCIÓN 2: Gestionar usuarios
# ══════════════════════════════════════════════════
gestionar_usuarios() {
    clear
    echo -e "${CYAN}${BOLD}══════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD} Gestión de Usuarios FTP${NC}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════${NC}\n"

    [[ ! -f "$VSFTPD_CONF" ]] && {
        echo -e "${RED}Primero instala el servidor FTP (Opción 1).${NC}"
        echo ""; read -rp "Presiona Enter..."; return
    }

    while true; do
        read -rp "Cantidad de usuarios a dar de alta/modificar: " NUM_USERS
        [[ "$NUM_USERS" =~ ^[1-9][0-9]*$ ]] && break
        echo "Número inválido."
    done
    echo ""

    for (( i=1; i<=NUM_USERS; i++ )); do
        echo -e "${BOLD}─── Usuario $i / $NUM_USERS ─────────────────────────${NC}"

        while true; do
            read -rp "  Nombre de usuario: " USERNAME
            USERNAME="${USERNAME,,}"
            [[ -n "$USERNAME" ]] && break
            echo "  No puede estar vacío."
        done

        while true; do
            read -rp "  Contraseña: " PASSWORD
            read -rp "  Confirmar contraseña: " PASSWORD2
            [[ "$PASSWORD" == "$PASSWORD2" && -n "$PASSWORD" ]] && break
            echo "  No coinciden o están vacías."
        done

        while true; do
            echo -e "  Grupo: [1] reprobados  [2] recursadores"
            read -rp "  Selección (1/2): " GRUPO_SEL
            case "$GRUPO_SEL" in
                1) GRUPO="reprobados";   break ;;
                2) GRUPO="recursadores"; break ;;
                *) echo "  Inválido." ;;
            esac
        done

        if id "$USERNAME" &>/dev/null; then
            OLD_GROUP=$(id -gn "$USERNAME")
            if [[ "$OLD_GROUP" != "$GRUPO" ]]; then
                echo "  Cambio de grupo: $OLD_GROUP → $GRUPO"
                detener_vsftpd
                limpiar_virtual_usuario "$USERNAME"
                usermod -g "$GRUPO" -aG ftp "$USERNAME"
                reconstruir_virtual_usuario "$USERNAME" "$GRUPO"
            else
                echo "  Sin cambio de grupo (ya es '$GRUPO')."
                if [[ ! -d "$VIRTUAL_ROOT/$USERNAME/$GRUPO" ]] || \
                   ! mountpoint -q "$VIRTUAL_ROOT/$USERNAME/$GRUPO" 2>/dev/null; then
                    detener_vsftpd
                    limpiar_virtual_usuario "$USERNAME"
                    reconstruir_virtual_usuario "$USERNAME" "$GRUPO"
                fi
            fi
            echo "  Usuario '$USERNAME' actualizado."
        else
            useradd -m -g "$GRUPO" -G ftp -s /sbin/nologin "$USERNAME"
            echo "  Usuario '$USERNAME' creado."
            detener_vsftpd
            reconstruir_virtual_usuario "$USERNAME" "$GRUPO"
        fi

        echo "$USERNAME:$PASSWORD" | chpasswd
        grep -qx "$USERNAME" "$VSFTPD_USER_LIST" || echo "$USERNAME" >> "$VSFTPD_USER_LIST"
        cat > "$VSFTPD_USERCONF/$USERNAME" << EOF
local_root=$VIRTUAL_ROOT/$USERNAME
write_enable=YES
local_umask=002
EOF
        echo -e "  ${GREEN}Configuración aplicada.${NC}"; echo ""
    done

    systemctl restart vsftpd
    echo -e "${GREEN}Gestión finalizada. Servicio FTP activo.${NC}"
    echo ""; read -rp "Presiona Enter para continuar..."
}

# ══════════════════════════════════════════════════
# OPCIÓN 3: Listar usuarios
# ══════════════════════════════════════════════════
listar_usuarios() {
    clear
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD} Usuarios FTP Registrados${NC}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════════════════${NC}\n"

    if [[ ! -f "$VSFTPD_USER_LIST" ]] || [[ ! -s "$VSFTPD_USER_LIST" ]]; then
        echo -e "${YELLOW}No hay usuarios registrados.${NC}"
    else
        printf "${BOLD}  %-18s | %-14s | %-35s${NC}\n" "USUARIO" "GRUPO" "CARPETAS VISIBLES"
        echo "  ──────────────────────────────────────────────────────────────────"
        while IFS= read -r user; do
            [[ -z "$user" || "$user" == \#* ]] && continue
            if [[ "$user" == "anonymous" ]]; then
                printf "  %-18s | %-14s | %-35s\n" "anonymous" "Público" "general (solo lectura)"
            elif id "$user" &>/dev/null; then
                grupo=$(id -gn "$user")
                vroot="$VIRTUAL_ROOT/$user"
                carpetas=""
                [[ -d "$vroot/general" ]] && carpetas+="general "
                [[ -d "$vroot/$grupo" ]]  && carpetas+="$grupo "
                [[ -d "$vroot/$user" ]]   && carpetas+="${user}(personal)"
                printf "  %-18s | %-14s | %-35s\n" "$user" "$grupo" "$carpetas"
            else
                printf "  %-18s | ${RED}No existe en el sistema${NC}\n" "$user"
            fi
        done < "$VSFTPD_USER_LIST"
    fi
    echo ""; read -rp "Presiona Enter para regresar al menú..."
}

# ══════════════════════════════════════════════════
# OPCIÓN 4: Actualizar permisos
# ══════════════════════════════════════════════════
actualizar_permisos() {
    clear
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║         ACTUALIZAR PERMISOS DE USUARIOS EXISTENTES          ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}\n"

    mapfile -t USUARIOS_FTP < <(grep -v '^anonymous$' "$VSFTPD_USER_LIST" 2>/dev/null | grep -v '^$' | grep -v '^#')

    if [[ ${#USUARIOS_FTP[@]} -eq 0 ]]; then
        echo -e "${YELLOW}  No hay usuarios FTP registrados.${NC}"
        echo ""; read -rp "Presiona Enter..."; return
    fi

    printf "  ${BOLD}%-4s | %-18s | %-14s | %-20s${NC}\n" "Nº" "USUARIO" "GRUPO ACTUAL" "ESTADO VIRTUAL"
    echo "  ──────────────────────────────────────────────────────────────"
    for idx in "${!USUARIOS_FTP[@]}"; do
        user="${USUARIOS_FTP[$idx]}"
        num=$((idx+1))
        if id "$user" &>/dev/null; then
            grupo=$(id -gn "$user")
            vroot="$VIRTUAL_ROOT/$user"
            if [[ -d "$vroot/$grupo" ]] && mountpoint -q "$vroot/$grupo" 2>/dev/null; then
                estado="${GREEN}OK${NC}"
            else
                estado="${RED}Necesita reparación${NC}"
            fi
            printf "  %-4s | %-18s | %-14s | " "$num" "$user" "$grupo"
            echo -e "$estado"
        else
            printf "  %-4s | %-18s | ${RED}No existe en el sistema${NC}\n" "$num" "$user"
        fi
    done

    echo ""
    echo -e "  ${BOLD}[A]${NC} Cambiar grupo a un usuario"
    echo -e "  ${BOLD}[R]${NC} Reparar todos los usuarios"
    echo -e "  ${BOLD}[V]${NC} Volver"
    echo ""
    read -rp "  Selección: " ACCION

    case "${ACCION^^}" in
        A)
            echo ""
            while true; do
                read -rp "  Número de usuario: " NUM_SEL
                [[ "$NUM_SEL" =~ ^[0-9]+$ ]] && \
                (( NUM_SEL >= 1 && NUM_SEL <= ${#USUARIOS_FTP[@]} )) && break
                echo "  Número inválido."
            done
            TARGET_USER="${USUARIOS_FTP[$((NUM_SEL-1))]}"
            id "$TARGET_USER" &>/dev/null || { echo -e "${RED}Usuario no existe.${NC}"; echo ""; read -rp "Enter..."; return; }
            OLD_GROUP=$(id -gn "$TARGET_USER")
            echo -e "\n  Usuario: ${BOLD}$TARGET_USER${NC} | Grupo actual: ${YELLOW}$OLD_GROUP${NC}\n"
            while true; do
                echo -e "  Nuevo grupo: [1] reprobados  [2] recursadores"
                read -rp "  Selección (1/2): " GRUPO_SEL
                case "$GRUPO_SEL" in
                    1) NUEVO_GRUPO="reprobados";   break ;;
                    2) NUEVO_GRUPO="recursadores"; break ;;
                    *) echo "  Inválido." ;;
                esac
            done
            echo ""
            detener_vsftpd
            limpiar_virtual_usuario "$TARGET_USER"
            usermod -g "$NUEVO_GRUPO" -aG ftp "$TARGET_USER"
            reconstruir_virtual_usuario "$TARGET_USER" "$NUEVO_GRUPO"
            cat > "$VSFTPD_USERCONF/$TARGET_USER" << EOF
local_root=$VIRTUAL_ROOT/$TARGET_USER
write_enable=YES
local_umask=002
EOF
            systemctl restart vsftpd
            echo -e "\n  ${GREEN}Grupo actualizado: $OLD_GROUP → $NUEVO_GRUPO${NC}"
            echo -e "  ${GREEN}Estructura virtual reconstruida.${NC}"
            echo ""; read -rp "Presiona Enter para continuar..."
            ;;
        R)
            echo ""
            detener_vsftpd
            echo -e "  Reparando acceso anónimo..."
            limpiar_anonimo
            echo -e "  ${GREEN}Anónimo reparado.${NC}"
            for user in "${USUARIOS_FTP[@]}"; do
                id "$user" &>/dev/null || continue
                grupo=$(id -gn "$user")
                echo -e "  Reconstruyendo '${BOLD}$user${NC}' (grupo: $grupo)..."
                limpiar_virtual_usuario "$user"
                reconstruir_virtual_usuario "$user" "$grupo"
                cat > "$VSFTPD_USERCONF/$user" << EOF
local_root=$VIRTUAL_ROOT/$user
write_enable=YES
local_umask=002
EOF
                echo -e "  ${GREEN}'$user' reparado.${NC}"
            done
            systemctl restart vsftpd
            echo -e "\n  ${GREEN}Todos reparados. Servicio FTP activo.${NC}"
            echo ""; read -rp "Presiona Enter para continuar..."
            ;;
        *) return ;;
    esac
}

# ══════════════════════════════════════════════════
# OPCIÓN 5: Eliminar usuarios
# ══════════════════════════════════════════════════
eliminar_usuarios() {
    clear
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║                   ELIMINAR USUARIOS FTP                     ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}\n"

    mapfile -t USUARIOS_FTP < <(grep -v '^anonymous$' "$VSFTPD_USER_LIST" 2>/dev/null | grep -v '^$' | grep -v '^#')

    if [[ ${#USUARIOS_FTP[@]} -eq 0 ]]; then
        echo -e "${YELLOW}  No hay usuarios FTP registrados para eliminar.${NC}"
        echo ""; read -rp "Presiona Enter para regresar..."; return
    fi

    printf "  ${BOLD}%-4s | %-18s | %-14s${NC}\n" "Nº" "USUARIO" "GRUPO"
    echo "  ────────────────────────────────────────"
    for idx in "${!USUARIOS_FTP[@]}"; do
        user="${USUARIOS_FTP[$idx]}"
        num=$((idx+1))
        if id "$user" &>/dev/null; then
            grupo=$(id -gn "$user")
            printf "  %-4s | %-18s | %-14s\n" "$num" "$user" "$grupo"
        else
            printf "  %-4s | %-18s | ${YELLOW}(sin cuenta del sistema)${NC}\n" "$num" "$user"
        fi
    done

    echo ""
    echo -e "  ${BOLD}[número]${NC}  Eliminar un usuario específico"
    echo -e "  ${BOLD}[T]${NC}       Eliminar TODOS los usuarios FTP"
    echo -e "  ${BOLD}[V]${NC}       Volver al menú principal"
    echo ""
    read -rp "  Selección: " ACCION

    # Función interna para borrar un usuario (SIN fuser)
    _borrar_usuario() {
        local user="$1"
        echo -e "\n  Eliminando '${BOLD}$user${NC}'..."

        # 1. Detener vsftpd (libera los bind mounts sin matar SSH)
        detener_vsftpd

        # 2. Limpiar estructura virtual (umount lazy si es necesario)
        limpiar_virtual_usuario "$user"
        echo -e "   ${GREEN}${NC} Carpeta virtual eliminada."

        # 3. Quitar de user_list
        sed -i "/^${user}$/d" "$VSFTPD_USER_LIST"
        echo -e "   ${GREEN}${NC} Eliminado de la lista de acceso FTP."

        # 4. Eliminar config individual
        rm -f "$VSFTPD_USERCONF/$user"
        echo -e "   ${GREEN}${NC} Config individual eliminada."

        # 5. Eliminar cuenta del sistema
        if id "$user" &>/dev/null; then
            userdel -r "$user" 2>/dev/null || userdel "$user" 2>/dev/null || true
            echo -e "   ${GREEN}${NC} Cuenta del sistema eliminada."
        fi

        echo -e "  ${GREEN}Usuario '$user' eliminado completamente.${NC}"
    }

    case "${ACCION^^}" in
        [0-9]*)
            NUM_SEL="$ACCION"
            if [[ "$NUM_SEL" =~ ^[0-9]+$ ]] && \
               (( NUM_SEL >= 1 && NUM_SEL <= ${#USUARIOS_FTP[@]} )); then
                TARGET_USER="${USUARIOS_FTP[$((NUM_SEL-1))]}"
                echo ""
                echo -e "  ${RED}${BOLD}¿Confirmas eliminar al usuario '$TARGET_USER'?${NC}"
                echo -e "  ${YELLOW}Esta acción no se puede deshacer.${NC}"
                read -rp "  Escribe 'si' para confirmar: " CONFIRMAR
                if [[ "${CONFIRMAR,,}" == "si" ]]; then
                    _borrar_usuario "$TARGET_USER"
                    systemctl restart vsftpd
                    echo -e "\n  ${GREEN}Servicio FTP reiniciado.${NC}"
                else
                    echo -e "\n  ${YELLOW}Operación cancelada.${NC}"
                fi
            else
                echo -e "  ${RED}Número inválido.${NC}"
            fi
            echo ""; read -rp "Presiona Enter para continuar..."
            ;;
        T)
            echo ""
            echo -e "  ${RED}${BOLD}¿Confirmas ELIMINAR TODOS los usuarios FTP?${NC}"
            echo -e "  ${YELLOW}Esta acción no se puede deshacer.${NC}"
            read -rp "  Escribe 'si' para confirmar: " CONFIRMAR
            if [[ "${CONFIRMAR,,}" == "si" ]]; then
                for user in "${USUARIOS_FTP[@]}"; do
                    _borrar_usuario "$user"
                done
                echo "anonymous" > "$VSFTPD_USER_LIST"
                systemctl restart vsftpd
                echo -e "\n  ${GREEN}Todos eliminados. Servicio FTP reiniciado.${NC}"
            else
                echo -e "\n  ${YELLOW}Operación cancelada.${NC}"
            fi
            echo ""; read -rp "Presiona Enter para continuar..."
            ;;
        V|*) return ;;
    esac
}

# ══════════════════════════════════════════════════
# MENÚ PRINCIPAL
# ══════════════════════════════════════════════════
while true; do
    clear
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║         ADMINISTRACIÓN SERVIDOR FTP              ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"

    if rpm -q vsftpd &>/dev/null; then
        SVC=$(systemctl is-active vsftpd 2>/dev/null || echo "inactivo")
        [[ "$SVC" == "active" ]] && STATUS="${GREEN}Instalado — Activo${NC}" \
                                 || STATUS="${YELLOW}Instalado — Detenido${NC}"
    else
        STATUS="${RED}No Instalado${NC}"
    fi

    echo -e "\n  Estado: $STATUS\n"
    echo -e "  ${BOLD}${CYAN}1)${NC} Instalar / Configurar servidor FTP"
    echo -e "  ${BOLD}${CYAN}2)${NC} Gestionar Usuarios  ${YELLOW}(crear / cambiar grupo)${NC}"
    echo -e "  ${BOLD}${CYAN}3)${NC} Listar Usuarios y Grupos"
    echo -e "  ${BOLD}${CYAN}4)${NC} Actualizar Permisos de Usuarios Existentes"
    echo -e "  ${BOLD}${CYAN}5)${NC} Eliminar Usuarios"
    echo -e "  ${BOLD}${CYAN}6)${NC} Salir"
    echo ""
    read -rp "  Elige una opción [1-6]: " OPCION

    case $OPCION in
        1) instalar_ftp ;;
        2) gestionar_usuarios ;;
        3) listar_usuarios ;;
        4) actualizar_permisos ;;
        5) eliminar_usuarios ;;
        6) echo "Saliendo..."; exit 0 ;;
        *) echo "Opción no válida."; sleep 1 ;;
    esac
done
