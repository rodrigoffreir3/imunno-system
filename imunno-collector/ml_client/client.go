// Arquivo: imunno-collector/ml_client/client.go

package ml_client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PredictionRequest é a estrutura enviada para o serviço de ML.
type PredictionRequest struct {
	ThreatScore int  `json:"threat_score"`
	FileSize    int  `json:"file_size"`
	IsPHP       bool `json:"is_php"`
	IsJS        bool `json:"is_js"`
}

// PredictionResponse é a estrutura recebida do serviço de ML.
type PredictionResponse struct {
	IsAnomaly  bool    `json:"is_anomaly"`
	Confidence float64 `json:"confidence"`
}

// MLClient é o cliente para o nosso serviço de IA.
type MLClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// New cria uma nova instância do MLClient.
func New(baseURL string) *MLClient {
	return &MLClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Predict envia os dados para o serviço de ML e retorna a predição.
func (c *MLClient) Predict(threatScore, fileSize int, isPHP, isJS bool) (*PredictionResponse, error) {
	requestURL := fmt.Sprintf("%s/predict", c.BaseURL)

	requestBody, err := json.Marshal(PredictionRequest{
		ThreatScore: threatScore,
		FileSize:    fileSize,
		IsPHP:       isPHP,
		IsJS:        isJS,
	})
	if err != nil {
		return nil, fmt.Errorf("erro ao converter requisição para JSON: %w", err)
	}

	req, err := http.NewRequest("POST", requestURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("erro ao criar requisição HTTP: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("erro ao enviar requisição para o serviço de ML: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("serviço de ML respondeu com status inesperado %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var predictionResponse PredictionResponse
	if err := json.NewDecoder(resp.Body).Decode(&predictionResponse); err != nil {
		return nil, fmt.Errorf("erro ao decodificar a resposta do serviço de ML: %w", err)
	}

	return &predictionResponse, nil
}
