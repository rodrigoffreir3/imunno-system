// Arquivo: imunno-agent/audit_monitor.go
package main

import (
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hpcloud/tail"
)

// regexParaLog é a nossa Expressão Regular para "quebrar" a linha de log do auditd
// e extrair as informações que queremos, como ppid, pid, e exe.
var regexParaLog = regexp.MustCompile(`type=SYSCALL.*? ppid=(\d+)\s+pid=(\d+).*? comm="([^"]+)".*? exe="([^"]+)"`)

// IniciarMonitorDeAuditoria é a nossa nova função principal de monitoramento.
func IniciarMonitorDeAuditoria() {
	auditLogPath := "/var/log/audit/audit.log"
	log.Printf("Iniciando monitoramento do log de auditoria do kernel em: %s", auditLogPath)

	// Espera um pouco para garantir que o serviço auditd já criou o arquivo de log.
	time.Sleep(2 * time.Second)

	// Configura o 'tail' para ler o arquivo em tempo real, começando do fim.
	t, err := tail.TailFile(auditLogPath, tail.Config{Follow: true, ReOpen: true})
	if err != nil {
		log.Fatalf("!!! ERRO FATAL: Não foi possível iniciar o monitoramento do log de auditoria: %v", err)
	}

	// Loop infinito que lê cada nova linha adicionada ao arquivo de log.
	for line := range t.Lines {
		// Para cada linha, tentamos extrair os dados do processo.
		dadosDoProcesso := parseAuditLogLine(line.Text)
		if dadosDoProcesso != nil {
			// Se a extração for bem-sucedida, registramos e enviamos o evento.
			log.Printf("+++ AUDIT: Novo processo detectado: PID=%d, Comando='%s'", dadosDoProcesso.ProcessID, dadosDoProcesso.Command)
			sendProcessEvent(*dadosDoProcesso)
		}
	}
}

// parseAuditLogLine usa nossa RegEx para extrair dados da linha de log.
func parseAuditLogLine(line string) *ProcessEvent {
	// Procuramos por linhas que correspondam à nossa regra de execução de comandos.
	if !strings.Contains(line, "type=SYSCALL") || !strings.Contains(line, "key=\"exec_rule\"") {
		return nil
	}

	matches := regexParaLog.FindStringSubmatch(line)

	// A RegEx deve encontrar 5 grupos: a string inteira, ppid, pid, comm, e exe.
	if len(matches) < 5 {
		return nil
	}

	// Convertendo os PIDs de string para número.
	ppid, _ := strconv.Atoi(matches[1])
	pid, _ := strconv.Atoi(matches[2])
	hostname, _ := os.Hostname()

	// Montamos nosso evento de processo com os dados extraídos.
	evento := &ProcessEvent{
		AgentID:   cfg.Agent.ID,
		Hostname:  hostname,
		Timestamp: time.Now(),
		ProcessID: int32(pid),
		ParentID:  int32(ppid),
		Command:   matches[4], // O caminho do executável
		Username:  "n/a",      // O log de auditoria padrão não nos dá o usuário facilmente, deixamos como n/a por ora.
	}

	return evento
}
