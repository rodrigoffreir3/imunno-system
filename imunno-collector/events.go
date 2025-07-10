// Arquivo: imunno-collector/events.go
package main

import "time"

// FileEvent define a estrutura para um alerta de arquivo.
type FileEvent struct {
	AgentID        string    `json:"agent_id"`
	Hostname       string    `json:"hostname"`
	FilePath       string    `json:"file_path"`
	FileHashSHA256 string    `json:"file_hash_sha256"`
	Timestamp      time.Time `json:"timestamp"`
	EventType      string    `json:"event_type"`
	Content        string    `json:"content,omitempty"`
}

// ProcessEvent define a estrutura para um alerta de novo processo.
type ProcessEvent struct {
	AgentID   string    `json:"agent_id"`
	Hostname  string    `json:"hostname"`
	Timestamp time.Time `json:"timestamp"`
	ProcessID int32     `json:"process_id"`
	ParentID  int32     `json:"parent_id"`
	Command   string    `json:"command"`
	Username  string    `json:"username"`
}
