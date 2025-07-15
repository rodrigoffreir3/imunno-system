// Arquivo: imunno-collector/config/config.go

package config

import (
	"os"
	"strconv"
)

// Config armazena todas as configurações da aplicação.
type Config struct {
	DBHost           string
	DBPort           string
	DBUser           string
	DBPassword       string
	DBName           string
	MLServiceURL     string
	EnableQuarantine bool
}

// Load carrega as configurações das variáveis de ambiente.
func Load() (*Config, error) {
	enableQuarantine, _ := strconv.ParseBool(os.Getenv("COLLECTOR_ENABLE_QUARANTINE"))

	return &Config{
		DBHost:           os.Getenv("DB_HOST"),
		DBPort:           os.Getenv("DB_PORT"),
		DBUser:           os.Getenv("DB_USER"),
		DBPassword:       os.Getenv("DB_PASSWORD"),
		DBName:           os.Getenv("DB_NAME"),
		MLServiceURL:     os.Getenv("ML_SERVICE_URL"),
		EnableQuarantine: enableQuarantine,
	}, nil
}
