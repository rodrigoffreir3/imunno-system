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

// Substitua APENAS a função main() no seu arquivo simulador_causalidade_v2.go

func main() {
	log.Println("--- INICIANDO SIMULAÇÃO 'GRAN FINALE' ---")
	collectorURL := os.Getenv("COLLECTOR_URL")
	if collectorURL == "" {
		collectorURL = "http://localhost:8080"
	}

	agentID := "gran-finale-agent-001"
	hostname := "servidor-alvo-final"
	apachePID := int32(200) // Usando PIDs diferentes para um novo teste
	phpPID := int32(40555)
	sleeperFilePath := "/var/www/html/wp-content/uploads/logo_updater.php" // Um nome de arquivo disfarçado

	// ETAPA 1: O "PAI" NASCE (PROCESSO BENIGNO)
	log.Printf("[ETAPA 1] Simulando o início do servidor Apache (PID: %d).", apachePID)
	sendProcessEvent(collectorURL, ProcessEvent{
		AgentID: agentID, Hostname: hostname, ProcessID: apachePID, ParentID: 1,
		Command: "/usr/sbin/apache2 -k start", Username: "root", Timestamp: time.Now(),
	})
	time.Sleep(2 * time.Second)

	// ETAPA 2: A INFILTRAÇÃO COM O ATAQUE MATRIOSCA
	log.Printf("[ETAPA 2] Injetando arquivo 'Matriosca' em: %s", sleeperFilePath)
	// --- ALTERAÇÃO APLICADA AQUI ---
	sleeperContentBytes, err := os.ReadFile("ataque_matriosca.php")
	if err != nil {
		log.Fatalf("ERRO: Não foi possível ler o arquivo 'ataque_matriosca.php'. Certifique-se de que ele está na pasta 'tools'.")
	}
	sleeperContent := string(sleeperContentBytes)
	// --- FIM DA ALTERAÇÃO ---

	sendFileEvent(collectorURL, FileEvent{
		AgentID: agentID, Hostname: hostname, FilePath: sleeperFilePath, Content: sleeperContent, Timestamp: time.Now(),
	})

	// O "TIMER"
	log.Println("[TIMER] Aguardando 15 segundos...")
	time.Sleep(15 * time.Second)

	// ETAPA 3: O DESPERTAR
	log.Printf("[ETAPA 3] Apache (PID: %d) executa o script Matriosca (novo PID: %d).", apachePID, phpPID)
	sendProcessEvent(collectorURL, ProcessEvent{
		AgentID: agentID, Hostname: hostname, ProcessID: phpPID, ParentID: apachePID,
		Command: fmt.Sprintf("/usr/bin/php %s", sleeperFilePath), Username: "www-data", Timestamp: time.Now(),
	})
	log.Println("--- SIMULAÇÃO 'GRAN FINALE' CONCLUÍDA ---")
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
