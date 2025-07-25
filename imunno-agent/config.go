// Arquivo: imunno-agent/config.go (Corrigido para não duplicar a URL)
package main

import (
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	Agent struct {
		ID            string
		QuarantineDir string
	}
	Collector struct {
		WebSocketURL string
		HTTPURL      string
	}
	Monitoring struct {
		WatchDir string
	}
}

func LoadConfig() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Aviso: não foi possível carregar .env: %v", err)
	}

	cfg := &Config{}

	cfg.Agent.ID = os.Getenv("AGENT_ID")
	cfg.Agent.QuarantineDir = os.Getenv("AGENT_QUARANTINE_DIR")
	cfg.Monitoring.WatchDir = os.Getenv("AGENT_WATCH_DIR")

	collectorURL := os.Getenv("COLLECTOR_URL")
	if collectorURL == "" {
		log.Println("AVISO: COLLECTOR_URL não definida, usando valor padrão 'ws://imunno_collector:8080/ws'")
		collectorURL = "ws://imunno_collector:8080/ws"
	}

	// --- CORREÇÃO APLICADA AQUI ---
	// Garante que a URL WebSocket seja exatamente a que foi definida no ambiente,
	// e constrói a URL HTTP a partir dela.
	cfg.Collector.WebSocketURL = collectorURL
	httpBaseURL := strings.Replace(collectorURL, "ws://", "http://", 1)
	httpBaseURL = strings.TrimSuffix(httpBaseURL, "/ws") // Remove o /ws para a base HTTP
	cfg.Collector.HTTPURL = httpBaseURL

	return cfg, nil
}
