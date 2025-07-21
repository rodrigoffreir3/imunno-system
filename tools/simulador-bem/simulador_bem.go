// Arquivo: tools/simulador-bem/simulador_bem.go
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Estruturas dos Eventos (as mesmas do seu sistema)
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

var (
	collectorURL string
	agentID      string
)

func main() {
	log.Println("--- Simulador de Atividades Benignas Ativado ---")

	collectorURL = os.Getenv("COLLECTOR_URL")
	if collectorURL == "" {
		// Fallback para desenvolvimento local se a variável de ambiente não for definida
		collectorURL = "http://localhost:8080"
	}
	agentID = "benign-sim-agent-001"

	n := flag.Int("n", 10, "Número de eventos benignos de cada tipo a serem gerados.")
	flag.Parse()

	log.Printf("Gerando %d eventos benignos de arquivo e processo...\n", *n)

	comandosBenignos := []string{
		"ls -l /var/www/html/wp-content/uploads",
		"grep -r 'DB_NAME' /var/www/html/wp-config.php",
		"/usr/sbin/apache2 -k graceful",
		"php /var/www/html/wp-cron.php",
		"find /tmp -name 'sess_*' -delete",
	}

	arquivosBenignos := []struct {
		Path    string
		Content string
	}{
		{"/var/www/html/wp-content/cache/page/index.html", ""},
		{"/var/www/html/wp-content/uploads/2025/07/imagem_nova.jpg", "CONTEUDO_FALSO_DE_IMAGEM_JPG"},
		{"/tmp/session_xyz123.tmp", "user_id|s:1:\"1\";"},
	}

	for i := 0; i < *n; i++ {
		arquivo := arquivosBenignos[rand.Intn(len(arquivosBenignos))]
		sendFileEvent(arquivo.Path, arquivo.Content)
		time.Sleep(1 * time.Second)

		comando := comandosBenignos[rand.Intn(len(comandosBenignos))]
		sendProcessEvent(comando)
		time.Sleep(1 * time.Second)
	}

	log.Println("--- Simulação Benigna Concluída ---")
}

func sendFileEvent(filePath, fileContent string) {
	event := FileEvent{
		AgentID:   agentID,
		Hostname:  "servidor-saudavel",
		FilePath:  filePath,
		Content:   fileContent,
		Timestamp: time.Now(),
	}
	jsonData, _ := json.Marshal(event)
	resp, err := http.Post(fmt.Sprintf("%s/v1/events/file", collectorURL), "application/json", bytes.NewBuffer(jsonData))
	handleResponse("Arquivo", filePath, resp, err)
}

func sendProcessEvent(command string) {
	event := ProcessEvent{
		AgentID:   agentID,
		Hostname:  "servidor-saudavel",
		ProcessID: int32(30000 + rand.Intn(1000)),
		ParentID:  int32(1),
		Command:   command,
		Username:  "www-data",
		Timestamp: time.Now(),
	}
	jsonData, _ := json.Marshal(event)
	resp, err := http.Post(fmt.Sprintf("%s/v1/events/process", collectorURL), "application/json", bytes.NewBuffer(jsonData))
	handleResponse("Processo", command, resp, err)
}

func handleResponse(eventType, detail string, resp *http.Response, err error) {
	if err != nil {
		log.Printf("[ERRO] Falha ao enviar evento de %s para %s: %v", eventType, collectorURL, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	log.Printf("[%s] Enviado: %s | Status: %s | Resposta: %s", eventType, filepath.Base(detail), resp.Status, string(body))
}
