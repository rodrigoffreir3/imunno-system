package config

import "os"

type Config struct {
	Agent      struct{ ID, QuarantineDir string }
	Collector  struct{ HTTP_URL, WebSocket_URL string }
	Monitoring struct{ WatchDir string }
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}
	cfg.Agent.ID = os.Getenv("AGENT_ID")
	cfg.Agent.QuarantineDir = os.Getenv("AGENT_QUARANTINE_DIR")

	collectorHost := "collector:" + os.Getenv("COLLECTOR_PORT")
	cfg.Collector.HTTP_URL = "http://" + collectorHost + "/v1/events"
	cfg.Collector.WebSocket_URL = "ws://" + collectorHost + "/ws"

	cfg.Monitoring.WatchDir = os.Getenv("AGENT_WATCH_DIR")
	return cfg, nil
}
