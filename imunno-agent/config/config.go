package config

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Agent struct {
		ID            string
		WatchDir      string
		QuarantineDir string
	}
	Collector struct {
		WebSocket_URL string
		HTTP_URL      string
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

	c := &Config{}

	c.Agent.ID = os.Getenv("AGENT_ID")
	c.Agent.WatchDir = os.Getenv("AGENT_WATCH_DIR")
	c.Agent.QuarantineDir = os.Getenv("AGENT_QUARANTINE_DIR")

	collectorHost := os.Getenv("COLLECTOR_HOST")
	if collectorHost == "" {
		collectorHost = "collector:8080"
	}
	c.Collector.WebSocket_URL = fmt.Sprintf("ws://%s/ws", collectorHost)
	c.Collector.HTTP_URL = fmt.Sprintf("http://%s/event", collectorHost)

	// Para reutilização
	c.Monitoring.WatchDir = c.Agent.WatchDir

	return c, nil
}
