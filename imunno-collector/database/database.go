package database

import (
	"context"
	"fmt"
	"imunno-collector/config"
	"imunno-collector/events"
	"log"
	"time"

	"github.com/jackc/pgx"
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
func (db *Database) InsertProcessEvent(agentID, hostname, command, username string, processID, parentID int32, threatScore int, timestamp time.Time) error {
	query := `INSERT INTO process_events (agent_id, hostname, command, username, process_id, parent_id, threat_score, timestamp)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := db.Pool.Exec(context.Background(), query, agentID, hostname, command, username, processID, parentID, threatScore, timestamp)
	return err
}

// UpdateFileEventThreatScore atualiza a pontuação de ameaça de um evento de arquivo.
func (db *Database) UpdateFileEventThreatScore(id int, newScore int) error {
	query := "UPDATE file_events SET threat_score = $1 WHERE id = $2"
	_, err := db.Pool.Exec(context.Background(), query, newScore, id)
	return err
}

// FindFileEventByTime busca por um evento de arquivo em um intervalo de tempo.
func (db *Database) FindFileEventByTime(hostname string, since time.Time) (*FileEvent, error) {
	var event FileEvent
	query := "SELECT id, file_path, threat_score FROM file_events WHERE hostname = $1 AND timestamp >= $2 ORDER BY timestamp DESC LIMIT 1"
	err := db.Pool.QueryRow(context.Background(), query, hostname, since).Scan(&event.ID, &event.FilePath, &event.ThreatScore)
	if err != nil {
		return nil, err
	}
	return &event, nil
}

// FileEvent representa a estrutura de dados para a tabela file_events.
type FileEvent struct {
	ID          int
	FilePath    string
	ThreatScore int
}

// Adicione esta função no final do arquivo database.go

// FindProcessByPID busca um evento de processo pelo seu ID de processo.
func (db *Database) FindProcessByPID(pid int32, hostname string) (*events.ProcessEvent, error) {
	query := `SELECT id, agent_id, hostname, process_id, parent_id, command, username, threat_score, timestamp 
	          FROM process_events 
	          WHERE process_id = $1 AND hostname = $2
	          ORDER BY timestamp DESC
	          LIMIT 1`

	var event events.ProcessEvent
	err := db.Pool.QueryRow(context.Background(), query, pid, hostname).Scan(
		&event.ID,
		&event.AgentID,
		&event.Hostname,
		&event.ProcessID,
		&event.ParentID,
		&event.Command,
		&event.Username,
		&event.ThreatScore,
		&event.Timestamp,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil // Retorna nil se nenhum processo for encontrado, não é um erro fatal.
		}
		return nil, err
	}

	return &event, nil
}
