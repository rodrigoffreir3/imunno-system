// Arquivo: imunno-agent/main.go (Versão Final e Corrigida)
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

	"github.com/gorilla/websocket"
)

// As structs duplicadas foram REMOVIDAS daqui.
// Elas agora vivem em events.go.

var cfg *Config
var arquivosVigiados = make(map[string]string)

func main() {
	var err error
	cfg, err = LoadConfig()
	if err != nil {
		log.Fatalf("Erro fatal ao carregar a configuração: %v", err)
	}

	go connectAndListen()
	go IniciarMonitorDeAuditoria() // A chamada agora está correta, sem argumentos.

	log.Printf("Iniciando monitoramento de arquivos em: %s (intervalo: 5 segundos)", cfg.Monitoring.WatchDir)
	for {
		patrulharDiretorio(cfg.Monitoring.WatchDir)
		time.Sleep(5 * time.Second)
	}
}

// Substitua a sua função patrulharDiretorio por esta versão mais inteligente

func patrulharDiretorio(dirPath string) {
	// Cria um mapa para marcar os arquivos que encontramos nesta varredura.
	arquivosAtuais := make(map[string]bool)

	filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if !d.IsDir() && (filepath.Ext(path) == ".php" || filepath.Ext(path) == ".js") {
			// Marca o arquivo como "presente" nesta varredura.
			arquivosAtuais[path] = true

			hashAtual, err := calcularHash(path)
			if err != nil {
				log.Printf("!!! Não foi possível calcular o hash de %s: %v", path, err)
				return nil
			}

			hashConhecido, existe := arquivosVigiados[path]

			// Se o arquivo não existia na nossa memória, é um evento de CRIAÇÃO.
			if !existe {
				log.Printf("+++ ARQUIVO NOVO DETECTADO (via polling): %s", path)
				arquivosVigiados[path] = hashAtual
				processAndSendFileEvent(path, "CREATE")
			} else if hashConhecido != hashAtual { // Se existia mas o hash mudou, é MODIFICAÇÃO.
				log.Printf("### ARQUIVO MODIFICADO DETECTADO (via polling): %s", path)
				arquivosVigiados[path] = hashAtual
				processAndSendFileEvent(path, "MODIFY")
			}
		}
		return nil
	})

	// Agora, a parte inteligente: verificamos se algum arquivo da nossa memória "sumiu".
	for path := range arquivosVigiados {
		if !arquivosAtuais[path] {
			log.Printf("--- ARQUIVO REMOVIDO DETECTADO: %s", path)
			// O arquivo foi removido (ou quarentenado), então o removemos da nossa memória.
			delete(arquivosVigiados, path)
		}
	}
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
		// Ignora silenciosamente qualquer outra ação que não seja um comando explícito para o agente.
		// Isso evita o spam de logs quando o hub faz broadcast de eventos gerais.
		return
	}
}

// Substitua a sua função handleQuarantineCommand por esta versão final e aprimorada

func handleQuarantineCommand(filePath string) {
	// --- ALTERAÇÃO: Verificação de existência do arquivo ---
	// Antes de tentar qualquer coisa, verifica se o arquivo realmente existe.
	// Isso evita logs de erro em cenários de simulação onde o arquivo não é criado fisicamente.
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[AVISO] Arquivo de evento simulado não encontrado para quarentena: %s. Ignorando.", filePath)
		return // Simplesmente para a execução do comando para este caso.
	}
	// --- FIM DA ALTERAÇÃO ---

	if err := os.MkdirAll(cfg.Agent.QuarantineDir, 0755); err != nil {
		log.Printf("!!! ERRO QUARENTENA: Não foi possível criar o diretório de quarentena: %v", err)
		return
	}

	// 1. Abre o arquivo de origem para leitura (do seu código funcional)
	sourceFile, err := os.Open(filePath)
	if err != nil {
		log.Printf("!!! ERRO QUARENTENA: Não foi possível abrir o arquivo de origem %s: %v", filePath, err)
		return
	}
	defer sourceFile.Close()

	fileName := filepath.Base(filePath)

	// --- ALTERAÇÃO 1: RENOMEANDO O ARQUIVO COM TIMESTAMP ---
	// Pega o timestamp atual e o adiciona ao início do nome do arquivo.
	timestamp := time.Now().Unix()
	destFileName := fmt.Sprintf("%d_%s", timestamp, fileName)
	destPath := filepath.Join(cfg.Agent.QuarantineDir, destFileName)
	// --- FIM DA ALTERAÇÃO 1 ---

	// 2. Cria o arquivo de destino na pasta de quarentena
	destFile, err := os.Create(destPath)
	if err != nil {
		log.Printf("!!! ERRO QUARENTENA: Não foi possível criar o arquivo de destino %s: %v", destPath, err)
		return
	}
	defer destFile.Close()

	// 3. Copia o conteúdo (do seu código funcional)
	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		os.Remove(destPath)
		log.Printf("!!! ERRO QUARENTENA: Falha ao copiar o conteúdo para o arquivo de quarentena: %v", err)
		return
	}

	sourceFile.Close()
	destFile.Close()

	// 4. Apaga o arquivo original (do seu código funcional)
	err = os.Remove(filePath)
	if err != nil {
		log.Printf("!!! ERRO QUARENTENA: Falha ao apagar o arquivo original %s após a cópia bem-sucedida: %v", filePath, err)
		return
	}

	log.Printf("+++ Arquivo %s movido com sucesso para a quarentena em %s", filePath, destPath)

	// --- ALTERAÇÃO 2: ATUALIZANDO A MEMÓRIA DO AGENTE ---
	// Após mover o arquivo, removemos ele da nossa memória interna.
	delete(arquivosVigiados, filePath)
	log.Printf("[MEMÓRIA] Registro do arquivo %s removido da memória do agente.", filePath)
	// --- FIM DA ALTERAÇÃO 2 ---
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
		log.Printf("O collector respondeu com um status inesperado para o evento de processo: %s", resp.Status)
	}
}
