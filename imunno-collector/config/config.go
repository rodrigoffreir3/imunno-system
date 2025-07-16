package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	DBURL            string
	MLServiceURL     string
	EnableQuarantine bool
}

// Load lê as variáveis de ambiente e constrói a configuração
func Load() (*Config, error) {
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("variável de ambiente DB_URL não definida")
	}

	mlURL := os.Getenv("ML_SERVICE_URL")
	if mlURL == "" {
		mlURL = "http://ml-service:5000/predict" // valor padrão
	}

	enableQuarantine := false
	if val := os.Getenv("ENABLE_QUARANTINE"); val != "" {
		parsed, err := strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("falha ao converter ENABLE_QUARANTINE: %v", err)
		}
		enableQuarantine = parsed
	}

	return &Config{
		DBURL:            dbURL,
		MLServiceURL:     mlURL,
		EnableQuarantine: enableQuarantine,
	}, nil
}
