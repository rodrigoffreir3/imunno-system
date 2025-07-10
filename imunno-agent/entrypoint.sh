#!/bin/sh

# Inicia o daemon (serviço) de auditoria em primeiro plano para logging.
# O auditd vai gerar os logs de execução de processos que vamos ler.
auditd -f &

# Dá um segundo para o serviço de auditoria iniciar completamente.
sleep 1

# Inicia nosso agente em primeiro plano.
# O 'exec' faz com que nosso agente se torne o processo principal do container,
# o que é uma boa prática para o gerenciamento de sinais do Docker.
exec ./imunno-agent