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
)

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
				event.ThreatScore, event.AnalysisFindings = analyzer.AnalyzeContent([]byte(event.Content))
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

		// A lógica de quarentena agora é executada após toda a análise.
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

// Substitua a sua função processEventHandler por esta

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

		// --- LÓGICA DE CORRELAÇÃO DE CAUSALIDADE APRIMORADA ---
		lineage, err := traceProcessLineage(db, &event)
		if err != nil {
			log.Printf("ERRO durante a análise de causalidade para o PID %d: %v", event.ProcessID, err)
		}

		// Itera sobre a linhagem para encontrar a origem
		for _, p := range lineage {
			// Extrai o caminho do arquivo do comando (ex: /usr/bin/php /var/www/...)
			parts := strings.Fields(p.Command)
			if len(parts) > 1 {
				filePath := parts[1]
				// Verifica se o comando executa um arquivo que existe no nosso banco
				fileOrigin, err := db.FindFileEventByPath(filePath, p.Hostname)
				if err != nil {
					log.Printf("ERRO ao buscar arquivo de origem para %s: %v", filePath, err)
					continue // Continua para o próximo processo na linhagem
				}

				if fileOrigin != nil {
					// ENCONTRAMOS A CONEXÃO!
					log.Printf("!!! CAUSALIDADE DETECTADA !!!")
					log.Printf("Processo PID %d originado do arquivo: %s", p.ProcessID, fileOrigin.FilePath)
					log.Printf("Score do arquivo de origem: %d. Score do processo: %d.", fileOrigin.ThreatScore, p.ThreatScore)

					// Soma os scores para criar um alerta de alta prioridade
					newScore := p.ThreatScore + fileOrigin.ThreatScore
					event.ThreatScore = newScore // Atualiza o score do evento atual
					log.Printf("Novo score de ameaça combinado por causalidade: %d", newScore)
					break // Para a busca assim que encontrar a primeira conexão
				}
			}
		}
		// --- FIM DA LÓGICA DE CORRELAÇÃO ---

		err = db.InsertProcessEvent(
			event.AgentID,
			event.Hostname,
			event.Command,
			event.Username,
			event.ProcessID,
			event.ParentID,
			event.ThreatScore, // Agora salva o score combinado, se houver
			event.Timestamp,
		)
		if err != nil {
			log.Printf("Erro ao inserir evento de processo no banco de dados: %v", err)
			http.Error(w, "Erro interno do servidor", http.StatusInternalServerError)
			return
		}

		eventJSON, _ := json.Marshal(event)
		h.Broadcast <- eventJSON

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

	// Lê o agent_id dos parâmetros da URL para identificar o cliente
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

// Substitua a sua função traceProcessLineage por esta versão mais robusta

func traceProcessLineage(db *database.Database, initialEvent *events.ProcessEvent) ([]*events.ProcessEvent, error) {
	lineage := []*events.ProcessEvent{initialEvent}
	currentEvent := initialEvent

	for i := 0; i < 5; i++ { // Limita a busca a 5 níveis
		if currentEvent.ParentID == 0 {
			break
		}

		log.Printf("[ANÁLISE DE CAUSALIDADE] Buscando pai do PID %d (PPID: %d)", currentEvent.ProcessID, currentEvent.ParentID)

		var parentEvent *events.ProcessEvent
		var err error

		// --- LÓGICA DE RETENTATIVA ADICIONADA AQUI ---
		// Tenta encontrar o pai 3 vezes, com uma pequena pausa, para dar tempo ao banco de dados.
		for attempt := 0; attempt < 3; attempt++ {
			parentEvent, err = db.FindProcessByPID(currentEvent.ParentID, currentEvent.Hostname)
			if err != nil {
				log.Printf("ERRO na tentativa %d de buscar processo pai: %v", attempt+1, err)
				return nil, err // Se o erro for real (não "não encontrado"), desiste.
			}
			if parentEvent != nil {
				break // Encontramos o pai, saia do loop de retentativa.
			}
			// Se não encontrou, espera um pouco e tenta de novo.
			time.Sleep(100 * time.Millisecond)
		}
		// --- FIM DA LÓGICA DE RETENTATIVA ---

		if parentEvent == nil {
			log.Printf("[ANÁLISE DE CAUSALIDADE] Pai (PPID: %d) não encontrado no banco de dados após múltiplas tentativas.", currentEvent.ParentID)
			break
		}

		lineage = append([]*events.ProcessEvent{parentEvent}, lineage...)
		currentEvent = parentEvent
	}

	return lineage, nil
}
