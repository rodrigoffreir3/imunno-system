// Arquivo: imunno-collector/events.go
// Esta é a nossa "Fonte Única da Verdade" para as estruturas de dados de eventos.

package events

import "time"

// FileEvent define a estrutura para todos os eventos relacionados a arquivos.
type FileEvent struct {
	ID               int       `json:"id"`
	AgentID          string    `json:"agent_id"`
	Hostname         string    `json:"hostname"`
	FilePath         string    `json:"file_path"`
	FileHashSHA256   string    `json:"file_hash_sha256"`
	ThreatScore      int       `json:"threat_score"`
	AnalysisFindings []byte    `json:"analysis_findings"` // JSONB é mapeado para []byte
	IsWhitelisted    bool      `json:"is_whitelisted"`
	QuarantinedPath  string    `json:"quarantined_path"`
	Timestamp        time.Time `json:"timestamp"`
	Content          string    `json:"content,omitempty"`
}

// ProcessEvent define a estrutura para todos os eventos relacionados a processos.
type ProcessEvent struct {
	ID          int       `json:"id"`
	AgentID     string    `json:"agent_id"`
	Hostname    string    `json:"hostname"`
	Timestamp   time.Time `json:"timestamp"`
	ProcessID   int32     `json:"process_id"`
	ParentID    int32     `json:"parent_id"`
	Command     string    `json:"command"`
	Username    string    `json:"username"`
	ThreatScore int       `json:"threat_score"`
}

// CommandMessage define a estrutura para um comando enviado do collector para o agent.
type CommandMessage struct {
	Action  string            `json:"action"`
	Payload map[string]string `json:"payload"`
}
