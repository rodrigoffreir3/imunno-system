// Arquivo: imunno-collector/main.go (Versão com lógica de Whitelist integrada)
package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"imunno-collector/analyzer"
	"imunno-collector/config"
	"imunno-collector/database"
	"imunno-collector/hub"
	"imunno-collector/ml_client"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A interface Store agora inclui a verificação da whitelist.
type Store interface {
	SaveFileEvent(ctx context.Context, event FileEvent, analysisResult analyzer.AnalysisResult) error
	SaveProcessEvent(ctx context.Context, event ProcessEvent, analysisResult analyzer.AnalysisResult) error
	FindRecentHighThreatFileEvent(ctx context.Context, agentID string, window time.Duration) (FileEvent, bool, error)
	ListRecentEvents(ctx context.Context, limit int) ([]map[string]interface{}, error)
	IsHashWhitelisted(ctx context.Context, hash string) (bool, error) // <-- NOSSA NOVA FUNÇÃO NA INTERFACE
}

// A struct DBStore permanece a mesma.
type DBStore struct {
	Pool *pgxpool.Pool
}

// Implementação da nova função da interface para DBStore.
func (s *DBStore) IsHashWhitelisted(ctx context.Context, hash string) (bool, error) {
	return database.IsHashWhitelisted(ctx, s.Pool, hash)
}

// As outras funções de banco de dados (SaveFileEvent, etc.) permanecem as mesmas.
func (s *DBStore) SaveFileEvent(ctx context.Context, event FileEvent, result analyzer.AnalysisResult) error {
	findingsJSON, err := json.Marshal(result.Findings)
	if err != nil {
		return err
	}
	sql := `INSERT INTO events (agent_id, hostname, file_path, file_hash_sha256, event_type, event_timestamp, threat_score, analysis_findings)
	         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err = s.Pool.Exec(ctx, sql,
		event.AgentID, event.Hostname, event.FilePath, event.FileHashSHA256,
		event.EventType, event.Timestamp, result.ThreatScore, findingsJSON)
	return err
}

func (s *DBStore) SaveProcessEvent(ctx context.Context, event ProcessEvent, result analyzer.AnalysisResult) error {
	sql := `INSERT INTO process_events (agent_id, hostname, event_timestamp, process_id, parent_id, command, username, threat_score)
	         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := s.Pool.Exec(ctx, sql,
		event.AgentID, event.Hostname, event.Timestamp,
		event.ProcessID, event.ParentID, event.Command, event.Username,
		result.ThreatScore)
	return err
}

func (s *DBStore) FindRecentHighThreatFileEvent(ctx context.Context, agentID string, window time.Duration) (FileEvent, bool, error) {
	var event FileEvent
	const THREAT_THRESHOLD = 40
	since := time.Now().Add(-window)
	sql := `SELECT file_path FROM events 
	         WHERE agent_id = $1 
	         AND threat_score >= $2
	         AND event_timestamp >= $3
	         ORDER BY event_timestamp DESC
	         LIMIT 1`
	err := s.Pool.QueryRow(ctx, sql, agentID, THREAT_THRESHOLD, since).Scan(&event.FilePath)
	if err != nil {
		if err.Error() == "no rows in result set" || err.Error() == "scany: no row was found" {
			return FileEvent{}, false, nil
		}
		return FileEvent{}, false, err
	}
	return event, true, nil
}

func (s *DBStore) ListRecentEvents(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	sql := `
    (SELECT 'file' as event_source, agent_id, hostname, event_timestamp, threat_score, analysis_findings::text as details FROM events)
    UNION ALL
    (SELECT 'process' as event_source, agent_id, hostname, event_timestamp, threat_score, command as details FROM process_events)
    ORDER BY event_timestamp DESC
    LIMIT $1;
    `
	rows, err := s.Pool.Query(ctx, sql, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []map[string]interface{}
	for rows.Next() {
		var eventSource, agentID, hostname, details string
		var eventTimestamp time.Time
		var threatScore int
		if err := rows.Scan(&eventSource, &agentID, &hostname, &eventTimestamp, &threatScore, &details); err != nil {
			return nil, err
		}
		eventMap := map[string]interface{}{
			"source":       eventSource,
			"agent_id":     agentID,
			"hostname":     hostname,
			"timestamp":    eventTimestamp.Format(time.RFC3339),
			"threat_score": threatScore,
			"details":      details,
		}
		events = append(events, eventMap)
	}
	return events, nil
}

// fileEventHandler AGORA COM A LÓGICA DE WHITELIST
func fileEventHandler(store Store, commandHub *hub.Hub, cfg config.Config) http.HandlerFunc {
	const THREAT_THRESHOLD = 40
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Erro ao ler o corpo da requisição", http.StatusInternalServerError)
			return
		}
		r.Body.Close()

		var event FileEvent
		if err := json.Unmarshal(bodyBytes, &event); err != nil {
			http.Error(w, "Corpo da requisição inválido", http.StatusBadRequest)
			return
		}

		log.Printf("=== Evento de Arquivo Recebido: %s (Agente: %s) ===", event.FilePath, event.AgentID)

		// >>>>>>>>>>>>>>>> INÍCIO DA LÓGICA DE WHITELIST <<<<<<<<<<<<<<<<
		isWhitelisted, err := store.IsHashWhitelisted(context.Background(), event.FileHashSHA256)
		if err != nil {
			log.Printf("!!! Erro ao checar a whitelist. Prosseguindo com a análise por segurança. Erro: %v", err)
		}

		if isWhitelisted {
			log.Printf("--- HASH SEGURO DETECTADO. O arquivo '%s' está na whitelist. Nenhuma análise necessária.", event.FilePath)
			// Se o arquivo é seguro, não fazemos nada e consideramos a pontuação como 0.
			// Podemos opcionalmente salvar o evento com score 0 se quisermos um log de tudo.
			w.WriteHeader(http.StatusAccepted)
			return // Interrompe a execução aqui.
		}
		// >>>>>>>>>>>>>>>> FIM DA LÓGICA DE WHITELIST <<<<<<<<<<<<<<<<

		content, err := os.ReadFile(event.FilePath)
		if err != nil {
			log.Printf("!!! AVISO: Não foi possível ler o conteúdo do arquivo %s para análise: %v", event.FilePath, err)
			event.Content = ""
		} else {
			event.Content = string(content)
		}

		analysisResult := analyzer.AnalisarConteudo(event.Content)
		log.Printf("... Análise de arquivo concluída. Pontuação: %d. Achados: %v", analysisResult.ThreatScore, analysisResult.Findings)

		if err := store.SaveFileEvent(context.Background(), event, analysisResult); err != nil {
			log.Printf("!!! Erro ao salvar evento de arquivo: %v", err)
			http.Error(w, "Erro interno", http.StatusInternalServerError)
			return
		}
		log.Printf("+++ Evento de arquivo salvo com sucesso!")

		if analysisResult.ThreatScore >= THREAT_THRESHOLD {
			log.Printf("!!! AMEAÇA DETECTADA! Pontuação (%d) acima do limite (%d).", analysisResult.ThreatScore, THREAT_THRESHOLD)
			if cfg.EnableQuarantine {
				log.Println(">>> Quarentena HABILITADA. Enviando ordem para o agente...")
				command := hub.CommandMessage{
					Action:  "quarantine",
					Payload: map[string]string{"file_path": event.FilePath},
				}
				if err := commandHub.SendCommandToAgent(event.AgentID, command); err != nil {
					log.Printf("!!! Erro ao enviar comando para o agente: %v", err)
				}
			} else {
				log.Println(">>> Quarentena DESABILITADA nas configurações. Nenhuma ordem de quarentena foi enviada.")
			}
		} else {
			log.Printf("--- Evento de arquivo de baixo risco. Nenhuma ação automática.")
		}

		go func() {
			mlEvent := ml_client.EventData{
				AgentID:   event.AgentID,
				Hostname:  event.Hostname,
				EventType: "FILE_EVENT",
				Details: map[string]interface{}{
					"file_path":         event.FilePath,
					"file_hash":         event.FileHashSHA256,
					"threat_score":      analysisResult.ThreatScore,
					"analysis_findings": analysisResult.Findings,
				},
			}
			ml_client.ForwardEvent(mlEvent, cfg.MLServiceURL)
		}()
		w.WriteHeader(http.StatusAccepted)
	}
}

// O resto do arquivo (processEventHandler, apiEventsHandler, main) permanece o mesmo.
func processEventHandler(store Store, commandHub *hub.Hub, cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}
		var event ProcessEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "Corpo da requisição inválido", http.StatusBadRequest)
			return
		}
		analysisResult := analyzer.AnalisarProcesso(event.Command)
		log.Printf("--- Evento de Processo Recebido: PID=%d, Comando='%s', Pontuação de Ameaça: %d ---", event.ProcessID, event.Command, analysisResult.ThreatScore)
		if err := store.SaveProcessEvent(context.Background(), event, analysisResult); err != nil {
			log.Printf("!!! Erro ao salvar evento de processo: %v", err)
		} else {
			log.Printf("+++ Evento de processo e análise salvos com sucesso!")
		}

		recentThreat, found, err := store.FindRecentHighThreatFileEvent(context.Background(), event.AgentID, 60*time.Second)
		if err != nil {
			log.Printf("!!! Erro ao buscar por ameaças recentes para correlação: %v", err)
		}
		if found {
			log.Printf("!!! CORRELAÇÃO DE AMEAÇA DETECTADA !!!")
			log.Printf("O processo (Score: %d) pode estar relacionado ao arquivo: %s", analysisResult.ThreatScore, recentThreat.FilePath)
			if cfg.EnableQuarantine {
				command := hub.CommandMessage{
					Action:  "quarantine",
					Payload: map[string]string{"file_path": recentThreat.FilePath},
				}
				if err := commandHub.SendCommandToAgent(event.AgentID, command); err != nil {
					log.Printf("!!! Erro ao enviar comando de quarentena por correlação: %v", err)
				}
			} else {
				log.Println(">>> Quarentena DESABILITADA, nenhuma ação de correlação foi tomada.")
			}
		}
		go func() {
			mlEvent := ml_client.EventData{
				AgentID:   event.AgentID,
				Hostname:  event.Hostname,
				EventType: "PROCESS_EVENT",
				Details: map[string]interface{}{
					"process_id":           event.ProcessID,
					"parent_id":            event.ParentID,
					"command":              event.Command,
					"username":             event.Username,
					"process_threat_score": analysisResult.ThreatScore,
					"process_findings":     analysisResult.Findings,
				},
			}
			ml_client.ForwardEvent(mlEvent, cfg.MLServiceURL)
		}()
		w.WriteHeader(http.StatusAccepted)
	}
}

func apiEventsHandler(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}
		events, err := store.ListRecentEvents(context.Background(), 50)
		if err != nil {
			log.Printf("!!! API_ERROR: Erro ao buscar eventos: %v", err)
			http.Error(w, "Erro interno do servidor", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	}
}

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Erro fatal ao carregar a configuração: %v", err)
	}

	dbPool, err := database.New(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Não foi possível conectar ao banco de dados: %v", err)
	}
	defer dbPool.Close()

	store := &DBStore{Pool: dbPool}
	commandHub := hub.NewHub()

	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/events", apiEventsHandler(store))

	mux.HandleFunc("/v1/events", fileEventHandler(store, commandHub, cfg))
	mux.HandleFunc("/v1/events/process", processEventHandler(store, commandHub, cfg))

	mux.HandleFunc("/ws", commandHub.ServeWs)

	fileServer := http.FileServer(http.Dir("./static"))
	mux.Handle("/", fileServer)

	log.Printf("Servidor 'imunno-collector' unificado iniciado na porta %s...", cfg.ServerPort)
	if err := http.ListenAndServe(":"+cfg.ServerPort, mux); err != nil {
		log.Fatalf("Erro ao iniciar o servidor: %v", err)
	}
}
