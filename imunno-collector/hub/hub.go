// Arquivo: imunno-collector/hub/hub.go (Corrigido e Aprimorado)

package hub

import (
	"imunno-collector/database"
	"log"
)

// Hub mantém o conjunto de clientes ativos e difunde mensagens para eles.
type Hub struct {
	Clients    map[*Client]bool
	Broadcast  chan []byte
	Register   chan *Client
	Unregister chan *Client
	DB         *database.Database
}

// NewHub cria uma nova instância de Hub.
func NewHub(db *database.Database) *Hub {
	return &Hub{
		Broadcast:  make(chan []byte),
		Register:   make(chan *Client),
		Unregister: make(chan *Client),
		Clients:    make(map[*Client]bool),
		DB:         db,
	}
}

// Run inicia o loop principal do hub.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.Register:
			h.Clients[client] = true
			log.Printf("Agente %s conectado.", client.AgentID)
		case client := <-h.Unregister:
			if _, ok := h.Clients[client]; ok {
				delete(h.Clients, client)
				close(client.Send)
				log.Printf("Agente %s desconectado.", client.AgentID)
			}
		case message := <-h.Broadcast:
			for client := range h.Clients {
				select {
				case client.Send <- message:
				default:
					close(client.Send)
					delete(h.Clients, client)
				}
			}
		}
	}
}

// --- FUNÇÃO ADICIONADA AQUI ---
// SendCommandToAgent encontra um cliente específico pelo ID e envia uma mensagem.
func (h *Hub) SendCommandToAgent(agentID string, message []byte) {
	for client := range h.Clients {
		if client.AgentID == agentID {
			select {
			case client.Send <- message:
				log.Printf("Comando enviado com sucesso para o agente %s.", agentID)
			default:
				log.Printf("AVISO: Canal do agente %s está cheio. O comando pode não ter sido enviado.", agentID)
			}
			return // Retorna após encontrar e enviar para o agente
		}
	}
	log.Printf("AVISO: Tentativa de enviar comando para o agente %s, mas ele não foi encontrado.", agentID)
}
