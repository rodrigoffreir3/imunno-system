// Arquivo: imunno-agent/main.go (Corrigido para a nova estrutura de pastas)
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	// A linha 'import "imunno-agent/config"' foi REMOVIDA daqui,
	// pois agora os arquivos estão no mesmo pacote.

	"github.com/gorilla/websocket"
)

// Agora ele encontra 'Config' diretamente, pois está no mesmo pacote.
var cfg *Config
var arquivosVigiados = make(map[string]string)

func main() {
	var err error
	// Agora ele encontra 'LoadConfig' diretamente.
	cfg, err = LoadConfig()
	if err != nil {
		log.Fatalf("Erro fatal ao carregar a configuração: %v", err)
	}

	// O resto do seu código main, sem alterações...
	processEventsChan := make(chan ProcessEvent)

	go connectAndListen()
	go IniciarMonitorDeAuditoria(processEventsChan)
	go listenForProcessEvents(processEventsChan)

	log.Printf("Iniciando monitoramento de arquivos em: %s (intervalo: 5 segundos)", cfg.Monitoring.WatchDir)
	for {
		patrulharDiretorio(cfg.Monitoring.WatchDir)
		time.Sleep(5 * time.Second)
	}
}

// --- NENHUMA ALTERAÇÃO DAQUI PARA BAIXO ---
// Todas as suas outras funções permanecem exatamente as mesmas.

func listenForProcessEvents(channel <-chan ProcessEvent) {
	for {
		event := <-channel
		log.Printf("+++ AUDIT: Novo processo detectado (via channel): PID=%d, Comando='%s'", event.ProcessID, event.Command)
		event.AgentID = cfg.Agent.ID
		sendProcessEvent(event)
	}
}

func patrulharDiretorio(dirPath string) {
	filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && filepath.Ext(path) == ".php" {
			hashAtual, err := calcularHash(path)
			if err != nil {
				log.Printf("!!! Não foi possível calcular o hash de %s: %v", path, err)
				return nil
			}
			hashConhecido, existe := arquivosVigiados[path]
			if !existe {
				log.Printf("+++ ARQUIVO NOVO DETECTADO (via polling): %s", path)
				arquivosVigiados[path] = hashAtual
				processAndSendFileEvent(path, "CREATE")
			} else if hashConhecido != hashAtual {
				log.Printf("### ARQUIVO MODIFICADO DETECTADO (via polling): %s", path)
				arquivosVigiados[path] = hashAtual
				processAndSendFileEvent(path, "MODIFY")
			}
		}
		return nil
	})
}

func calcularHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func connectAndListen() {
	for {
		u, _ := url.Parse(cfg.Collector.WebSocketURL)
		q := u.Query()
		q.Set("agent_id", cfg.Agent.ID)
		u.RawQuery = q.Encode()
		log.Printf("Conectando ao Hub de Comando em %s", u.String())
		conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
		if err != nil {
			log.Printf("!!! Erro ao conectar ao WebSocket, tentando novamente em 10s: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}
		log.Printf("+++ Conectado ao Hub de Comando!")
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				log.Printf("!!! Erro ao ler mensagem do WebSocket, reconectando...: %v", err)
				break
			}
			var cmd CommandMessage
			if err := json.Unmarshal(message, &cmd); err != nil {
				log.Printf("!!! Erro ao decodificar comando JSON: %v", err)
				continue
			}
			log.Printf("<<< Comando recebido: %s", cmd.Action)
			handleCommand(cmd)
		}
		conn.Close()
	}
}

func handleCommand(cmd CommandMessage) {
	switch cmd.Action {
	case "quarantine":
		filePath, ok := cmd.Payload["file_path"]
		if !ok {
			log.Println("!!! Comando 'quarantine' sem 'file_path' no payload.")
			return
		}
		handleQuarantineCommand(filePath)
	default:
		log.Printf("Aviso: Comando desconhecido recebido: %s", cmd.Action)
	}
}

func handleQuarantineCommand(filePath string) {
	if err := os.MkdirAll(cfg.Agent.QuarantineDir, 0755); err != nil {
		log.Printf("!!! ERRO QUARENTENA: Não foi possível criar o diretório: %v", err)
		return
	}
	fileName := filepath.Base(filePath)
	destPath := filepath.Join(cfg.Agent.QuarantineDir, fileName)
	if err := os.Rename(filePath, destPath); err != nil {
		log.Printf("!!! ERRO QUARENTENA: Falha ao mover o arquivo %s: %v", filePath, err)
		return
	}
	log.Printf("+++ Arquivo %s movido com sucesso para a quarentena em %s", filePath, destPath)
}

func processAndSendFileEvent(filePath string, eventType string) {
	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Aviso: Não foi possível ler o arquivo %s: %v", filePath, err)
		return
	}

	hash := sha256.New()
	hash.Write(contentBytes)
	hashString := fmt.Sprintf("%x", hash.Sum(nil))
	hostname, _ := os.Hostname()

	eventData := FileEvent{
		AgentID:        cfg.Agent.ID,
		Hostname:       hostname,
		FilePath:       filePath,
		FileHashSHA256: hashString,
		Timestamp:      time.Now(),
		EventType:      eventType,
		Content:        string(contentBytes),
	}

	jsonData, err := json.Marshal(eventData)
	if err != nil {
		log.Printf("Erro ao converter evento de arquivo para JSON: %v", err)
		return
	}
	resp, err := http.Post(cfg.Collector.HTTPURL+"/v1/events/file", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("!!! Erro ao enviar evento de arquivo: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		log.Printf("O collector respondeu com status inesperado para evento de arquivo: %s", resp.Status)
	}
}

func sendProcessEvent(event ProcessEvent) {
	processEventURL := cfg.Collector.HTTPURL + "/v1/events/process"
	jsonData, err := json.Marshal(event)
	if err != nil {
		log.Printf("Erro ao converter evento de processo para JSON: %v", err)
		return
	}
	resp, err := http.Post(processEventURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("!!! Erro ao enviar evento de processo: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		log.Printf("O collector respondeu com status inesperado para evento de processo: %s", resp.Status)
	}
}
