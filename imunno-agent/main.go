// Arquivo completo e corrigido: imunno-agent/main.go
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

	"imunno-agent/config"

	"github.com/gorilla/websocket"
)

var cfg *config.Config
var arquivosVigiados = make(map[string]string)

func main() {
	var err error
	cfg, err = config.LoadConfig()
	if err != nil {
		log.Fatalf("Erro fatal ao carregar a configuração: %v", err)
	}

	// 2. AGORA que 'cfg' está preenchida e pronta, podemos iniciar os 'funcionários'
	// que dependem dela.
	go connectAndListen()
	go IniciarMonitorDeAuditoria()

	// 3. A patrulha de arquivos (a tarefa do 'chefe') começa por último.
	log.Printf("Iniciando monitoramento de arquivos em: %s (intervalo: 5 segundos)", cfg.Monitoring.WatchDir)
	for {
		patrulharDiretorio(cfg.Monitoring.WatchDir)
		time.Sleep(5 * time.Second)
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
				processAndSendEvent(path, "CREATE")
			} else if hashConhecido != hashAtual {
				log.Printf("### ARQUIVO MODIFICADO DETECTADO (via polling): %s", path)
				arquivosVigiados[path] = hashAtual
				processAndSendEvent(path, "MODIFY")
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
		u, _ := url.Parse(cfg.Collector.WebSocket_URL)
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
		log.Printf("!!! ERRO QUARENTENA: Não foi possível criar ou verificar o diretório de quarentena: %v", err)
		return
	}
	sourceFile, err := os.Open(filePath)
	if err != nil {
		log.Printf("!!! ERRO QUARENTENA: Não foi possível abrir o arquivo de origem %s: %v", filePath, err)
		return
	}
	defer sourceFile.Close()
	fileName := filepath.Base(filePath)
	destPath := filepath.Join(cfg.Agent.QuarantineDir, fileName)
	destFile, err := os.Create(destPath)
	if err != nil {
		log.Printf("!!! ERRO QUARENTENA: Não foi possível criar o arquivo de destino %s: %v", destPath, err)
		return
	}
	defer destFile.Close()
	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		os.Remove(destPath)
		log.Printf("!!! ERRO QUARENTENA: Falha ao copiar o conteúdo para o arquivo de quarentena: %v", err)
		return
	}
	sourceFile.Close()
	destFile.Close()
	err = os.Remove(filePath)
	if err != nil {
		log.Printf("!!! ERRO QUARENTENA: Falha ao apagar o arquivo original %s após a cópia bem-sucedida: %v", filePath, err)
		return
	}
	log.Printf("+++ Arquivo %s movido com sucesso para a quarentena em %s", filePath, destPath)
}

func processAndSendEvent(filePath string, eventType string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Aviso: Não foi possível abrir o arquivo %s: %v", filePath, err)
		return
	}
	defer file.Close()
	contentBytes, err := io.ReadAll(file)
	if err != nil {
		log.Printf("!!! Erro ao ler o conteúdo do arquivo %s: %v", filePath, err)
		return
	}
	file.Seek(0, 0)
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
	sendEvent(eventData)
}

func sendEvent(event FileEvent) {
	jsonData, err := json.Marshal(event)
	if err != nil {
		log.Printf("Erro ao converter evento para JSON: %v", err)
		return
	}
	resp, err := http.Post(cfg.Collector.HTTP_URL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("!!! Erro ao enviar evento de arquivo: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		log.Printf("O collector respondeu com um status inesperado para o evento de arquivo: %s", resp.Status)
	}
}

func sendProcessEvent(event ProcessEvent) {
	processEventURL := cfg.Collector.HTTP_URL + "/process"
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
		log.Printf("O collector respondeu com um status inesperado para o evento de processo: %s", resp.Status)
	}
}
