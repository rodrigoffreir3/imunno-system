// Arquivo: imunno-collector/hub/hub.go

package hub

import (
	"imunno-collector/database"
	"log"
	"time"
)

// Constantes para o WebSocket
const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 512
)

// Hub mantém o conjunto de clientes ativos.
type Hub struct {
	Clients    map[*Client]bool
	Broadcast  chan []byte
	Register   chan *Client
	Unregister chan *Client
	DB         *database.Database
}

// NewHub cria uma nova instância do Hub.
func NewHub(db *database.Database) *Hub {
	return &Hub{
		Broadcast:  make(chan []byte),
		Register:   make(chan *Client),
		Unregister: make(chan *Client),
		Clients:    make(map[*Client]bool),
		DB:         db,
	}
}

// Run inicia o processamento de mensagens do hub.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.Register:
			h.Clients[client] = true
			log.Println("Novo cliente WebSocket registrado.")
		case client := <-h.Unregister:
			if _, ok := h.Clients[client]; ok {
				delete(h.Clients, client)
				close(client.Send)
				log.Println("Cliente WebSocket desregistrado.")
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
