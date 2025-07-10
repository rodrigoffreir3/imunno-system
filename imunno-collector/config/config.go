package config

import (
	"os"
	"strconv" // Pacote necessário para converter string para booleano
)

type Config struct {
	ServerPort       string
	DatabaseURL      string
	MLServiceURL     string
	EnableQuarantine bool // Nosso novo campo de configuração
}

func LoadConfig() (Config, error) {
	var cfg Config
	cfg.ServerPort = os.Getenv("COLLECTOR_PORT")
	cfg.DatabaseURL = os.Getenv("DB_URL")
	cfg.MLServiceURL = os.Getenv("ML_SERVICE_URL")

	// Lê a nova variável e converte para booleano.
	// Se a variável não existir, o padrão será 'false'.
	enableQuarantineStr := os.Getenv("COLLECTOR_ENABLE_QUARANTINE")
	cfg.EnableQuarantine, _ = strconv.ParseBool(enableQuarantineStr)

	return cfg, nil
}
