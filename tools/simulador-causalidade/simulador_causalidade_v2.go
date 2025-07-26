package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type FileEvent struct {
	AgentID   string    `json:"agent_id"`
	Hostname  string    `json:"hostname"`
	FilePath  string    `json:"file_path"`
	Content   string    `json:"content,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type ProcessEvent struct {
	AgentID   string    `json:"agent_id"`
	Hostname  string    `json:"hostname"`
	ProcessID int32     `json:"process_id"`
	ParentID  int32     `json:"parent_id"`
	Command   string    `json:"command"`
	Username  string    `json:"username"`
	Timestamp time.Time `json:"timestamp"`
}

func main() {
	log.Println("--- INICIANDO SIMULADOR DE CAUSALIDADE v2 (HISTÓRIA COMPLETA) ---")
	collectorURL := os.Getenv("COLLECTOR_URL")
	if collectorURL == "" {
		collectorURL = "http://localhost:8080"
	}

	agentID := "causality-sim-agent-002"
	hostname := "servidor-alvo-v2"
	apachePID := int32(150)
	phpPID := int32(30123)
	sleeperFilePath := "/var/www/html/uploads/cache_update_v2.php"

	// ETAPA 1: O "PAI" NASCE E É SALVO NO BANCO
	log.Printf("[ETAPA 1] Simulando o início do servidor Apache (PID: %d).", apachePID)
	sendProcessEvent(collectorURL, ProcessEvent{
		AgentID: agentID, Hostname: hostname, ProcessID: apachePID, ParentID: 1,
		Command: "/usr/sbin/apache2 -k start", Username: "root", Timestamp: time.Now(),
	})
	time.Sleep(2 * time.Second)

	// ETAPA 2: A INFILTRAÇÃO
	log.Printf("[ETAPA 2] Injetando arquivo 'sleeper agent' em: %s", sleeperFilePath)
	sleeperContent := "<?php /* Script malicioso v2 */ system($_GET['exec']); ?>"
	sendFileEvent(collectorURL, FileEvent{
		AgentID: agentID, Hostname: hostname, FilePath: sleeperFilePath, Content: sleeperContent, Timestamp: time.Now(),
	})

	// O "TIMER"
	log.Println("[TIMER] Aguardando 15 segundos...")
	time.Sleep(15 * time.Second)

	// ETAPA 3: O DESPERTAR (O "FILHO" NASCE DO "PAI" QUE JÁ ESTÁ NO BANCO)
	log.Printf("[ETAPA 3] Apache (PID: %d) executa o script malicioso (novo PID: %d).", apachePID, phpPID)
	sendProcessEvent(collectorURL, ProcessEvent{
		AgentID: agentID, Hostname: hostname, ProcessID: phpPID, ParentID: apachePID,
		Command: fmt.Sprintf("/usr/bin/php %s", sleeperFilePath), Username: "www-data", Timestamp: time.Now(),
	})
	log.Println("--- SIMULAÇÃO DE CAUSALIDADE v2 CONCLUÍDA ---")
}

func sendFileEvent(collectorURL string, event FileEvent) {
	jsonData, _ := json.Marshal(event)
	resp, err := http.Post(fmt.Sprintf("%s/v1/events/file", collectorURL), "application/json", bytes.NewBuffer(jsonData))
	if err == nil {
		resp.Body.Close()
	}
}

func sendProcessEvent(collectorURL string, event ProcessEvent) {
	jsonData, _ := json.Marshal(event)
	resp, err := http.Post(fmt.Sprintf("%s/v1/events/process", collectorURL), "application/json", bytes.NewBuffer(jsonData))
	if err == nil {
		resp.Body.Close()
	}
}
