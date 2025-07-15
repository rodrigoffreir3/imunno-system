// Arquivo: imunno-collector/hub/hub.go

package hub

import (
	"imunno-collector/database"
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
		case client := <-h.Unregister:
			if _, ok := h.Clients[client]; ok {
				delete(h.Clients, client)
				close(client.Send)
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
