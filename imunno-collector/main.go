package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"imunno-collector/analyzer"
	"imunno-collector/config"
	"imunno-collector/database"
	"imunno-collector/events"
	"imunno-collector/hub"
	"imunno-collector/ml_client"

	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5" // --- CORREÇÃO APLICADA AQUI ---
)

// main continua igual
func main() {
	log.Println("--- INICIANDO IMUNNO COLLECTOR ---")

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("CRÍTICO: Não foi possível carregar a configuração: %v", err)
	}

	var db *database.Database
	for i := 0; i < 10; i++ {
		db, err = database.New(cfg)
		if err == nil {
			log.Println(">>> SUCESSO: Conexão com o banco de dados estabelecida!")
			break
		}
		log.Printf(">>> TENTATIVA %d/10: Falha ao conectar ao banco de dados: %v. Tentando novamente em 5 segundos...", i+1, err)
		time.Sleep(5 * time.Second)
	}
	if err != nil {
		log.Fatalf("CRÍTICO: Não foi possível estabelecer conexão com o banco de dados após múltiplas tentativas. Desistindo. Erro final: %v", err)
	}

	h := hub.NewHub(db)
	go h.Run()

	mlClient := ml_client.New(cfg.MLServiceURL)

	http.HandleFunc("/v1/events/file", fileEventHandler(db, h, mlClient, cfg.EnableQuarantine))
	http.HandleFunc("/v1/events/process", processEventHandler(db, h))
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(h, w, r)
	})

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	log.Println("Servidor iniciado na porta 8080. Aguardando agentes...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Falha ao iniciar o servidor: %v", err)
	}
}

func fileEventHandler(db *database.Database, h *hub.Hub, mlClient *ml_client.MLClient, enableQuarantine bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}

		var event events.FileEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "Erro ao decodificar o corpo da requisição", http.StatusBadRequest)
			return
		}

		log.Printf("Evento de arquivo recebido de %s: %s", event.AgentID, event.FilePath)

		isWhitelisted, err := db.IsHashWhitelisted(event.FileHashSHA256)
		if err != nil {
			log.Printf("Erro ao verificar whitelist para o hash %s: %v", event.FileHashSHA256, err)
		}
		event.IsWhitelisted = isWhitelisted

		if isWhitelisted {
			log.Printf("Arquivo %s (%s) está na whitelist. Ignorando análise.", event.FilePath, event.FileHashSHA256)
			event.ThreatScore = 0
		} else {
			if event.Content != "" {
				event.ThreatScore, event.AnalysisFindings = analyzer.AnalyzeContent([]byte(event.Content), event.FilePath)
				log.Printf("Análise heurística concluída para %s. Pontuação de ameaça inicial: %d", event.FilePath, event.ThreatScore)

				fileSize := len(event.Content)
				isPHP := strings.HasSuffix(strings.ToLower(event.FilePath), ".php")
				isJS := strings.HasSuffix(strings.ToLower(event.FilePath), ".js")

				prediction, err := mlClient.Predict(event.ThreatScore, fileSize, isPHP, isJS)
				if err != nil {
					log.Printf("Erro ao chamar o serviço de ML: %v", err)
				} else {
					log.Printf("Predição da IA: Anomalia=%t, Confiança=%.2f", prediction.IsAnomaly, prediction.Confidence)
					if prediction.IsAnomaly {
						log.Printf("IA DETECTOU ANOMALIA. Elevando a pontuação de ameaça.")
						event.ThreatScore = 95
					}
				}
			} else {
				log.Printf("Evento de arquivo %s não contém conteúdo para análise.", event.FilePath)
				event.ThreatScore = 0
			}
		}

		if enableQuarantine && event.ThreatScore >= 70 {
			log.Printf("AMEAÇA CRÍTICA DETECTADA [Score: %d] para o arquivo %s. Enviando comando de quarentena para o agente %s.", event.ThreatScore, event.FilePath, event.AgentID)

			quarantineCommand := events.CommandMessage{
				Action: "quarantine",
				Payload: map[string]string{
					"file_path": event.FilePath,
				},
			}

			commandJSON, _ := json.Marshal(quarantineCommand)
			h.SendCommandToAgent(event.AgentID, commandJSON)
		}

		_, err = db.InsertFileEvent(
			event.AgentID,
			event.Hostname,
			event.FilePath,
			event.FileHashSHA256,
			event.Content,
			event.ThreatScore,
			event.AnalysisFindings,
			event.IsWhitelisted,
			event.QuarantinedPath,
			event.Timestamp,
		)
		if err != nil {
			log.Printf("Erro ao inserir evento de arquivo no banco de dados: %v", err)
			http.Error(w, "Erro interno do servidor", http.StatusInternalServerError)
			return
		}

		eventJSON, _ := json.Marshal(event)
		h.Broadcast <- eventJSON

		w.WriteHeader(http.StatusAccepted)
	}
}

func processEventHandler(db *database.Database, h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}

		var event events.ProcessEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "Erro ao decodificar o corpo da requisição", http.StatusBadRequest)
			return
		}

		log.Printf("Evento de processo recebido de %s: PID=%d, PPID=%d, Comando=%s", event.AgentID, event.ProcessID, event.ParentID, event.Command)

		err := db.InsertProcessEvent(
			event.AgentID,
			event.Hostname,
			event.Command,
			event.Username,
			event.ProcessID,
			event.ParentID,
			event.ThreatScore,
			event.Timestamp,
		)
		if err != nil {
			log.Printf("Erro ao inserir evento de processo no banco de dados: %v", err)
			http.Error(w, "Erro interno do servidor", http.StatusInternalServerError)
			return
		}

		eventJSON, _ := json.Marshal(event)
		h.Broadcast <- eventJSON

		go func(eventToInvestigate events.ProcessEvent) {
			time.Sleep(200 * time.Millisecond)

			lineage, err := traceProcessLineage(db, &eventToInvestigate)
			if err != nil {
				log.Printf("ERRO durante a análise de causalidade para o PID %d: %v", eventToInvestigate.ProcessID, err)
			}

			if len(lineage) > 1 {
				log.Printf("--- INÍCIO DA LINHAGEM DO PROCESSO (PID: %d) ---", eventToInvestigate.ProcessID)
				isCorrelated := false
				for _, p := range lineage {
					log.Printf("  -> PID: %d (Pai: %d) | Comando: %s", p.ProcessID, p.ParentID, p.Command)
					parts := strings.Fields(p.Command)
					if len(parts) > 1 {
						filePath := parts[1]
						fileOrigins, err := db.FindFileEventsInTimeWindow(p.Hostname, p.Timestamp, 10*time.Minute)
						if err != nil {
							log.Printf("ERRO ao buscar arquivos de origem para %s: %v", filePath, err)
							continue
						}

						for _, file := range fileOrigins {
							if file.FilePath == filePath && file.ThreatScore > 0 {
								log.Printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
								log.Printf("!!! CAUSALIDADE DETECTADA !!!")
								log.Printf("!!! Processo PID %d originado do arquivo: %s", p.ProcessID, file.FilePath)

								originalProcessScore := eventToInvestigate.ThreatScore
								newScore := originalProcessScore + file.ThreatScore
								eventToInvestigate.ThreatScore = newScore

								log.Printf("!!! Score do Arquivo: %d | Score Original do Processo: %d | Novo Score Combinado: %d", file.ThreatScore, originalProcessScore, newScore)
								log.Printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

								db.UpdateProcessEventScore(eventToInvestigate.ID, newScore)
								updatedEventJSON, _ := json.Marshal(eventToInvestigate)
								h.Broadcast <- updatedEventJSON
								isCorrelated = true
								break
							}
						}
					}
					if isCorrelated {
						break
					}
				}
				log.Printf("--- FIM DA LINHAGEM DO PROCESSO ---")
			}
		}(event)

		w.WriteHeader(http.StatusAccepted)
	}
}

func serveWs(h *hub.Hub, w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}

	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		log.Println("AVISO: Conexão WebSocket recebida sem agent_id.")
		agentID = "unknown"
	}

	client := &hub.Client{Hub: h, Conn: conn, Send: make(chan []byte, 256), AgentID: agentID}
	client.Hub.Register <- client

	go client.WritePump()
	go client.ReadPump()
}

func traceProcessLineage(db *database.Database, initialEvent *events.ProcessEvent) ([]*events.ProcessEvent, error) {
	lineage := []*events.ProcessEvent{initialEvent}
	currentEvent := initialEvent

	for i := 0; i < 5; i++ {
		if currentEvent.ParentID == 0 {
			break
		}

		log.Printf("[ANÁLISE DE CAUSALIDADE] Buscando pai do PID %d (PPID: %d)", currentEvent.ProcessID, currentEvent.ParentID)

		parentEvent, err := db.FindProcessByPID(currentEvent.ParentID, currentEvent.Hostname)
		if err != nil {
			if err == pgx.ErrNoRows {
				log.Printf("[ANÁLISE DE CAUSALIDADE] Pai (PPID: %d) não encontrado no banco de dados.", currentEvent.ParentID)
				break
			}
			return nil, err
		}

		if parentEvent == nil {
			break
		}

		lineage = append([]*events.ProcessEvent{parentEvent}, lineage...)
		currentEvent = parentEvent
	}

	return lineage, nil
}
