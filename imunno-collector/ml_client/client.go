// Arquivo: imunno-collector/ml_client/client.go
package ml_client

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

// EventData é a estrutura que nosso serviço Python espera receber.
type EventData struct {
	AgentID   string                 `json:"agent_id"`
	Hostname  string                 `json:"hostname"`
	EventType string                 `json:"event_type"`
	Details   map[string]interface{} `json:"details"`
}

// ForwardEvent envia um evento para o serviço de ML para análise.
func ForwardEvent(eventData EventData, mlServiceURL string) {
	jsonData, err := json.Marshal(eventData)
	if err != nil {
		log.Printf("!!! ML_CLIENT: Erro ao converter evento para JSON: %v", err)
		return
	}

	resp, err := http.Post(mlServiceURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("!!! ML_CLIENT: Erro ao enviar evento para o serviço de ML: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("!!! ML_CLIENT: Serviço de ML respondeu com status inesperado: %s", resp.Status)
		return
	}

	log.Println("--- Evento encaminhado com sucesso para o serviço de ML.")
}
