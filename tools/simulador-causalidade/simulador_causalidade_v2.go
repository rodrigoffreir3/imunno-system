package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
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
	log.Println("--- INICIANDO SIMULADOR DE CAUSALIDADE v2 ---")

	// Pega a URL do Collector do ambiente ou usa um padrão
	collectorURL := os.Getenv("COLLECTOR_URL")
	if collectorURL == "" {
		collectorURL = "http://localhost:8080"
	}

	// Pega o número de eventos do primeiro argumento da linha de comando
	numEvents := 10 // Padrão
	if len(os.Args) > 1 {
		n, err := strconv.Atoi(os.Args[1])
		if err == nil {
			numEvents = n
		}
	}

	log.Printf("Simulando %d pares de eventos (criação de arquivo + execução de processo)...", numEvents)

	agentID := "causality-agent-002"
	hostname := "webserver-prod-03"
	basePID := int32(5000)

	for i := 0; i < numEvents; i++ {
		currentPID := basePID + int32(i)
		filePath := fmt.Sprintf("/var/www/html/uploads/temp_script_%d.php", currentPID)
		content := fmt.Sprintf("<?php echo 'hello from %d'; ?>", currentPID)

		// 1. Evento de Criação de Arquivo
		log.Printf("[%d/%d] Criando arquivo: %s", i+1, numEvents, filePath)
		fileEvent := FileEvent{
			AgentID:   agentID,
			Hostname:  hostname,
			FilePath:  filePath,
			Content:   content,
			Timestamp: time.Now(),
		}
		sendEvent(collectorURL, "/v1/events/file", fileEvent)

		// Pequeno atraso para simular realismo
		time.Sleep(500 * time.Millisecond)

		// 2. Evento de Execução de Processo (com o arquivo recém-criado)
		log.Printf("[%d/%d] Executando processo para o arquivo: %s (PID: %d)", i+1, numEvents, filePath, currentPID)
		processEvent := ProcessEvent{
			AgentID:   agentID,
			Hostname:  hostname,
			ProcessID: currentPID,
			ParentID:  1234, // PID pai genérico para o servidor web (ex: Apache, Nginx)
			Command:   fmt.Sprintf("/usr/bin/php %s", filePath),
			Username:  "www-data",
			Timestamp: time.Now(),
		}
		sendEvent(collectorURL, "/v1/events/process", processEvent)

		time.Sleep(1 * time.Second)
	}

	log.Println("--- SIMULAÇÃO DE CAUSALIDADE v2 CONCLUÍDA ---")
}

func sendEvent(collectorURL, path string, data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Erro ao converter evento para JSON: %v", err)
		return
	}

	resp, err := http.Post(fmt.Sprintf("%s%s", collectorURL, path), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Erro ao enviar evento para %s: %v", path, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		log.Printf("Resposta inesperada do collector para %s: %s", path, resp.Status)
	}
}