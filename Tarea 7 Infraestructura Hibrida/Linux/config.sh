#!/bin/bash
# ============================================================
# config.sh - Variables globales compartidas (AlmaLinux)
# ============================================================

CFG_DOMAIN="reprobados.com"

# ── Rutas FTP servidor ────────────────────────────────────────
CFG_FTP_BASE="/srv/ftp"
CFG_FTP_REPO="$CFG_FTP_BASE/repo"

# ── Descarga FTP cliente ──────────────────────────────────────
CFG_FTP_REPO_BASE="/repo/http/Linux"
CFG_DOWNLOAD_DIR="/tmp/practica7_downloads"

# ── Certificados SSL (PKI) ────────────────────────────────────
CFG_SSL_DIR="/etc/ssl/practica7"
CFG_SSL_CRT="$CFG_SSL_DIR/server.crt"
CFG_SSL_KEY="$CFG_SSL_DIR/server.key"
CFG_SSL_P12="$CFG_SSL_DIR/server.p12" # Requerido para Tomcat
CFG_SSL_PASS="reprobados"