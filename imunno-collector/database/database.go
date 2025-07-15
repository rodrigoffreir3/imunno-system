// Arquivo: imunno-collector/database/database.go

package database

import (
	"context"
	"fmt"
	"imunno-system/imunno-collector/config" // Caminho completo do import
	"log"
	"time"

	"github.com/jackc/pgx/v5"
)

// Database representa a conexão com o banco de dados.
type Database struct {
	Conn *pgx.Conn
}

// New cria uma nova conexão com o banco de dados.
func New(cfg *config.Config) (*Database, error) {
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName)
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		return nil, fmt.Errorf("não foi possível conectar ao banco de dados: %w", err)
	}
	log.Println("Conexão com o banco de dados PostgreSQL estabelecida com sucesso.")
	return &Database{Conn: conn}, nil
}

// IsHashWhitelisted verifica se um hash de arquivo está na lista de permissões.
func (db *Database) IsHashWhitelisted(hash string) (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM known_good_hashes WHERE file_hash_sha256 = $1)"
	err := db.Conn.QueryRow(context.Background(), query, hash).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// InsertFileEvent insere um novo evento de arquivo no banco de dados.
func (db *Database) InsertFileEvent(event interface{}) error {
	// Esta função precisará de um type assertion para acessar os campos
	// mas a conexão em si estará correta.
	// Exemplo: e := event.(main.FileEvent)
	query := `INSERT INTO file_events (agent_id, hostname, file_path, file_hash_sha256, threat_score, analysis_findings, is_whitelisted, quarantined_path, timestamp)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	// A lógica de inserção precisará ser ajustada para passar os campos corretos.
	// _, err := db.Conn.Exec(context.Background(), query, ...)
	return nil // Implementação temporária
}

// InsertProcessEvent insere um novo evento de processo no banco de dados.
func (db *Database) InsertProcessEvent(event interface{}) error {
	query := `INSERT INTO process_events (agent_id, hostname, process_id, parent_id, command, username, threat_score, timestamp)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	// _, err := db.Conn.Exec(context.Background(), query, ...)
	return nil // Implementação temporária
}

// UpdateFileEventThreatScore atualiza a pontuação de ameaça de um evento de arquivo.
func (db *Database) UpdateFileEventThreatScore(id int, newScore int) error {
	query := "UPDATE file_events SET threat_score = $1 WHERE id = $2"
	_, err := db.Conn.Exec(context.Background(), query, newScore, id)
	return err
}

// FindFileEventByTime busca por um evento de arquivo em um intervalo de tempo.
func (db *Database) FindFileEventByTime(hostname string, since time.Time) (interface{}, error) {
	// Lógica de busca...
	return nil, nil // Implementação temporária
}
