#!/bin/sh

# Garante que o diretório e o arquivo de log existem com permissões adequadas
mkdir -p /var/log/audit
touch /var/log/audit/audit.log
chmod 640 /var/log/audit/audit.log

# Inicia o daemon de auditoria em foreground (para manter o container vivo)
echo "[INFO] Iniciando auditd..."
auditd -f &
AUDITD_PID=$!

# Aguarda o auditd subir completamente
sleep 1

# Verifica se o auditd ainda está rodando
if ! kill -0 "$AUDITD_PID" 2>/dev/null; then
    echo "[ERRO] auditd falhou ao iniciar. Verifique a configuração em /etc/audit/auditd.conf"
    exit 1
fi

echo "[INFO] Iniciando imunno-agent..."
exec ./imunno-agent
