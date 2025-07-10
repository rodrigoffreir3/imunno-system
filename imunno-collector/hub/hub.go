// Arquivo: imunno-collector/hub/hub.go
package hub

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

// upgrader irá 'promover' uma conexão HTTP para uma conexão WebSocket.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// Em produção, devemos verificar a origem da requisição (r.Header.Get("Origin"))
	CheckOrigin: func(r *http.Request) bool { return true },
}

// CommandMessage define a estrutura de um comando enviado para um agente.
type CommandMessage struct {
	Action  string      `json:"action"`
	Payload interface{} `json:"payload"`
}

// Client representa um único agente conectado via WebSocket.
type Client struct {
	hub     *Hub
	conn    *websocket.Conn
	agentID string
}

// Hub gerencia o conjunto de todos os clientes (agentes) conectados.
type Hub struct {
	clients    map[string]*Client // Mapeia agentID para o Client
	clientsMux sync.RWMutex       // Mutex para proteger o acesso concorrente ao mapa de clientes
}

// NewHub cria uma nova instância do Hub.
func NewHub() *Hub {
	return &Hub{
		clients: make(map[string]*Client),
	}
}

// ServeWs trata das requisições WebSocket vindas dos agentes.
func (h *Hub) ServeWs(w http.ResponseWriter, r *http.Request) {
	// Pega o ID do agente dos parâmetros da URL (ex: /ws?agent_id=agent-001)
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		http.Error(w, "agent_id é obrigatório", http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}

	client := &Client{hub: h, conn: conn, agentID: agentID}
	h.register(client)

	log.Printf("+++ Agente conectado: %s", agentID)

	// Opcional: podemos criar um loop aqui para ler mensagens do agente, se necessário.
	// Por enquanto, apenas o mantemos conectado.
}

// register adiciona um novo cliente ao hub.
func (h *Hub) register(client *Client) {
	h.clientsMux.Lock()
	defer h.clientsMux.Unlock()
	h.clients[client.agentID] = client
}

// unregister remove um cliente (não implementado o gatilho, mas a função está aqui).
func (h *Hub) unregister(agentID string) {
	h.clientsMux.Lock()
	defer h.clientsMux.Unlock()
	if _, ok := h.clients[agentID]; ok {
		delete(h.clients, agentID)
		log.Printf("--- Agente desconectado: %s", agentID)
	}
}

// SendCommandToAgent envia um comando específico para um agente específico.
func (h *Hub) SendCommandToAgent(agentID string, command CommandMessage) error {
	h.clientsMux.RLock()
	defer h.clientsMux.RUnlock()

	client, ok := h.clients[agentID]
	if !ok {
		log.Printf("Aviso: Tentativa de enviar comando para agente desconhecido ou offline: %s", agentID)
		return nil // Não é um erro fatal, o agente pode estar offline.
	}

	log.Printf(">>> Enviando comando '%s' para o agente %s", command.Action, agentID)

	// Converte o comando para JSON
	msg, err := json.Marshal(command)
	if err != nil {
		return err
	}

	// Envia a mensagem pelo WebSocket
	return client.conn.WriteMessage(websocket.TextMessage, msg)
}
