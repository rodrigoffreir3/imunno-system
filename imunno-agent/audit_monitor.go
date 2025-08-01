// Arquivo: imunno-agent/audit_monitor.go (Versão Simplificada e Corrigida)
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

// Sua RegEx, que já estava ótima.
var regexParaLog = regexp.MustCompile(`type=SYSCALL.*? ppid=(\d+)\s+pid=(\d+).*? comm="([^"]+)".*? exe="([^"]+)"`)

// A função agora é mais simples e não usa mais canais.
func IniciarMonitorDeAuditoria() {
	auditLogPath := "/var/log/audit/audit.log"
	log.Printf("Iniciando monitoramento do log de auditoria do kernel em: %s", auditLogPath)

	time.Sleep(2 * time.Second)

	t, err := tail.TailFile(auditLogPath, tail.Config{Follow: true, ReOpen: true})
	if err != nil {
		log.Fatalf("!!! ERRO FATAL: Não foi possível iniciar o monitoramento do log de auditoria: %v", err)
	}

	for line := range t.Lines {
		dadosDoProcesso := parseAuditLogLine(line.Text)
		if dadosDoProcesso != nil {
			log.Printf("+++ AUDIT: Novo processo detectado: PID=%d, Comando='%s'", dadosDoProcesso.ProcessID, dadosDoProcesso.Command)
			// Chama a função global diretamente, como o monitor de arquivos.
			sendProcessEvent(*dadosDoProcesso)
		}
	}
}

func parseAuditLogLine(line string) *ProcessEvent {
	if !strings.Contains(line, "type=SYSCALL") || !strings.Contains(line, "key=\"exec_rule\"") {
		return nil
	}
	matches := regexParaLog.FindStringSubmatch(line)
	if len(matches) < 5 {
		return nil
	}

	ppid, _ := strconv.Atoi(matches[1])
	pid, _ := strconv.Atoi(matches[2])
	hostname, _ := os.Hostname()

	evento := &ProcessEvent{
		AgentID:   cfg.Agent.ID, // O AgentID é preenchido aqui
		Hostname:  hostname,
		Timestamp: time.Now(),
		ProcessID: int32(pid),
		ParentID:  int32(ppid),
		Command:   matches[4],
		Username:  "n/a",
	}

	return evento
}
