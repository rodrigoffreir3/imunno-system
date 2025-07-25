// Arquivo: imunno-agent/audit_monitor.go (Versão Final e Corrigida)
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

var regexParaLog = regexp.MustCompile(`type=SYSCALL.*? ppid=(\d+)\s+pid=(\d+).*? comm="([^"]+)".*? exe="([^"]+)"`)

func IniciarMonitorDeAuditoria(eventsChan chan<- ProcessEvent) {
	auditLogPath := "/var/log/audit/audit.log"
	log.Printf("Iniciando monitoramento do log de auditoria do kernel em: %s", auditLogPath)

	go func() {
		time.Sleep(2 * time.Second)

		t, err := tail.TailFile(auditLogPath, tail.Config{Follow: true, ReOpen: true})
		if err != nil {
			log.Printf("!!! ERRO: Não foi possível iniciar o monitoramento do log de auditoria: %v", err)
			return
		}

		for line := range t.Lines {
			dadosDoProcesso := parseAuditLogLine(line.Text)
			if dadosDoProcesso != nil {
				eventsChan <- *dadosDoProcesso
			}
		}
	}()
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
	command := matches[4]

	evento := &ProcessEvent{
		Hostname:  hostname,
		Timestamp: time.Now(),
		ProcessID: int32(pid),
		ParentID:  int32(ppid),
		Command:   command,
		Username:  "n/a",
	}

	return evento
}
