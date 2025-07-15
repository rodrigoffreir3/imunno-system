// Arquivo: imunno-collector/main.go

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	// --- IMPORTAÇÕES CORRIGIDAS ---
	"imunno-collector/analyzer"
	"imunno-collector/config"
	"imunno-collector/database"
	"imunno-collector/hub"
	"imunno-collector/ml_client"

	"github.com/gorilla/websocket"
)

// A função main agora está mais limpa e focada em orquestrar os componentes.
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

	hub := hub.NewHub(db)
	go hub.Run()

	mlClient := ml_client.New(cfg.MLServiceURL)

	http.HandleFunc("/v1/events/file", fileEventHandler(db, hub, mlClient, cfg.EnableQuarantine))
	http.HandleFunc("/v1/events/process", processEventHandler(db, hub))
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	log.Println("Servidor iniciado na porta 8080. Aguardando agentes...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Falha ao iniciar o servidor: %v", err)
	}
}

// fileEventHandler lida com todos os eventos de arquivo recebidos.
func fileEventHandler(db *database.Database, hub *hub.Hub, mlClient *ml_client.MLClient, enableQuarantine bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}

		var event FileEvent
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
			content, err := os.ReadFile(event.FilePath)
			if err != nil {
				log.Printf("Erro ao ler o arquivo %s para análise: %v", event.FilePath, err)
			} else {
				event.ThreatScore, event.AnalysisFindings = analyzer.AnalyzeContent(content)
				log.Printf("Análise heurística concluída para %s. Pontuação de ameaça: %d", event.FilePath, event.ThreatScore)

				fileSize, _ := getFileSize(event.FilePath)
				isPHP := strings.HasSuffix(strings.ToLower(event.FilePath), ".php")
				isJS := strings.HasSuffix(strings.ToLower(event.FilePath), ".js")

				prediction, err := mlClient.Predict(event.ThreatScore, fileSize, isPHP, isJS)
				if err != nil {
					log.Printf("Erro ao chamar o serviço de ML: %v", err)
				} else {
					log.Printf("Predição da IA: Anomalia=%t, Confiança=%.2f", prediction.IsAnomaly, prediction.Confidence)
					if prediction.IsAnomaly && prediction.Confidence > 0.75 {
						event.ThreatScore += 20
						log.Printf("Pontuação de ameaça aumentada pela IA para %d", event.ThreatScore)
					}
				}
			}
		}

		if enableQuarantine && event.ThreatScore >= 40 {
			quarantinedPath, err := quarantineFile(event.FilePath)
			if err != nil {
				log.Printf("FALHA AO COLOCAR EM QUARENTENA o arquivo %s: %v", event.FilePath, err)
			} else {
				log.Printf("SUCESSO: Arquivo %s movido para quarentena em %s", event.FilePath, quarantinedPath)
				event.QuarantinedPath = quarantinedPath
			}
		}

		if err := db.InsertFileEvent(&event); err != nil {
			log.Printf("Erro ao inserir evento de arquivo no banco de dados: %v", err)
			http.Error(w, "Erro interno do servidor", http.StatusInternalServerError)
			return
		}

		eventJSON, _ := json.Marshal(event)
		hub.Broadcast <- eventJSON

		w.WriteHeader(http.StatusAccepted)
	}
}

// processEventHandler lida com todos os eventos de processo recebidos.
func processEventHandler(db *database.Database, hub *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}

		var event ProcessEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "Erro ao decodificar o corpo da requisição", http.StatusBadRequest)
			return
		}

		log.Printf("Evento de processo recebido de %s: PID=%d, Comando=%s", event.AgentID, event.ProcessID, event.Command)

		if err := db.InsertProcessEvent(&event); err != nil {
			log.Printf("Erro ao inserir evento de processo no banco de dados: %v", err)
			http.Error(w, "Erro interno do servidor", http.StatusInternalServerError)
			return
		}

		eventJSON, _ := json.Marshal(event)
		hub.Broadcast <- eventJSON

		w.WriteHeader(http.StatusAccepted)
	}
}

// serveWs lida com as conexões WebSocket.
func serveWs(hub *hub.Hub, w http.ResponseWriter, r *http.Request) {
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
	client := &hub.Client{Hub: hub, Conn: conn, Send: make(chan []byte, 256)}
	client.Hub.Register <- client

	go client.WritePump()
	go client.ReadPump()
}

func getFileSize(filePath string) (int, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}
	return int(fileInfo.Size()), nil
}

func quarantineFile(filePath string) (string, error) {
	quarantineDir := "/quarantine"
	if _, err := os.Stat(quarantineDir); os.IsNotExist(err) {
		if err := os.MkdirAll(quarantineDir, 0755); err != nil {
			return "", fmt.Errorf("não foi possível criar o diretório de quarentena: %w", err)
		}
	}

	sourceFile, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("não foi possível abrir o arquivo de origem: %w", err)
	}
	defer sourceFile.Close()

	fileName := filepath.Base(filePath)
	timestamp := time.Now().Unix()
	destFileName := fmt.Sprintf("%d_%s.infected", timestamp, fileName)
	destPath := filepath.Join(quarantineDir, destFileName)

	destFile, err := os.Create(destPath)
	if err != nil {
		return "", fmt.Errorf("não foi possível criar o arquivo de destino na quarentena: %w", err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return "", fmt.Errorf("não foi possível copiar o arquivo para a quarentena: %w", err)
	}

	sourceFile.Close()

	err = os.Remove(filePath)
	if err != nil {
		return "", fmt.Errorf("não foi possível remover o arquivo original após a quarentena: %w", err)
	}

	return destPath, nil
}

func getEnvAsInt(name string, defaultValue int) int {
	valueStr := os.Getenv(name)
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}
