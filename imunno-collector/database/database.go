package database

import (
	"context"
	"fmt"
	"imunno-collector/config"
	"imunno-collector/events"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Database representa o pool de conexões com o banco de dados.
type Database struct {
	Pool *pgxpool.Pool
}

// New cria um novo pool de conexões com o banco de dados.
func New(cfg *config.Config) (*Database, error) {
	if cfg.DBURL == "" {
		return nil, fmt.Errorf("DB_URL está vazio. Verifique o arquivo .env")
	}

	pool, err := pgxpool.New(context.Background(), cfg.DBURL)
	if err != nil {
		return nil, fmt.Errorf("não foi possível criar o pool de conexão: %w", err)
	}

	// Testa a conexão
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("não foi possível conectar ao banco de dados: %w", err)
	}

	log.Println("Conexão com o banco de dados PostgreSQL estabelecida com sucesso.")
	return &Database{Pool: pool}, nil
}

// IsHashWhitelisted verifica se um hash de arquivo está na lista de permissões.
func (db *Database) IsHashWhitelisted(hash string) (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM known_good_hashes WHERE file_hash_sha256 = $1)"
	err := db.Pool.QueryRow(context.Background(), query, hash).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// InsertFileEvent insere um novo evento de arquivo no banco de dados.
func (db *Database) InsertFileEvent(agentID, hostname, filePath, fileHash, fileContent string, threatScore int, findings []byte, isWhitelisted bool, quarantinedPath string, timestamp time.Time) (int, error) {
	var eventID int
	query := `INSERT INTO file_events (agent_id, hostname, file_path, file_hash_sha256, file_content, threat_score, analysis_findings, is_whitelisted, quarantined_path, timestamp)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`
	err := db.Pool.QueryRow(context.Background(), query, agentID, hostname, filePath, fileHash, fileContent, threatScore, findings, isWhitelisted, quarantinedPath, timestamp).Scan(&eventID)
	return eventID, err
}

// InsertProcessEvent insere um novo evento de processo no banco de dados.
func (db *Database) InsertProcessEvent(event events.ProcessEvent) error {
	query := `INSERT INTO process_events (agent_id, hostname, command, username, process_id, parent_id, threat_score, origin_hash, timestamp)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := db.Pool.Exec(context.Background(), query, event.AgentID, event.Hostname, event.Command, event.Username, event.ProcessID, event.ParentID, event.ThreatScore, event.OriginHash, event.Timestamp)
	return err
}

// UpdateFileEventThreatScore atualiza a pontuação de ameaça de um evento de arquivo.
func (db *Database) UpdateFileEventThreatScore(id int, newScore int) error {
	query := "UPDATE file_events SET threat_score = $1 WHERE id = $2"
	_, err := db.Pool.Exec(context.Background(), query, newScore, id)
	return err
}

// FindOriginFileEvent busca o evento de arquivo mais provável que originou um processo.
// Ele procura pelo evento de arquivo mais recente no mesmo host, ocorrido até 30s antes do processo.
func (db *Database) FindOriginFileEvent(hostname string, processTimestamp time.Time) (*events.FileEvent, error) {
	var origin events.FileEvent
	windowStart := processTimestamp.Add(-30 * time.Second)

	query := `
		SELECT id, file_path, file_hash_sha256, file_content, threat_score
		FROM file_events
		WHERE hostname = $1
		  AND timestamp BETWEEN $2 AND $3
		ORDER BY timestamp DESC
		LIMIT 1`

	err := db.Pool.QueryRow(context.Background(), query, hostname, windowStart, processTimestamp).Scan(
		&origin.ID,
		&origin.FilePath,
		&origin.FileHashSHA256,
		&origin.Content,
		&origin.ThreatScore,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil // Nenhum arquivo encontrado na janela de tempo, não é um erro.
		}
		return nil, err // Outro erro de banco de dados.
	}

	return &origin, nil
}

// AddHashToWhitelist adiciona um novo hash de arquivo à tabela de whitelist.
func (db *Database) AddHashToWhitelist(hash, fileName, source string) error {
	query := `INSERT INTO known_good_hashes (file_hash_sha256, file_name, software_source)
	          VALUES ($1, $2, $3) ON CONFLICT (file_hash_sha256) DO NOTHING`
	_, err := db.Pool.Exec(context.Background(), query, hash, fileName, source)
	return err
}
