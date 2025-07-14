# Arquivo: imunno-ml-service/main.py

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import logging
import os

# Configuração do logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Modelos de Dados (Contrato da API) ---
class EventData(BaseModel):
    threat_score: int = Field(..., alias="threat_score")
    file_size: int = Field(..., alias="file_size")
    is_php: bool = Field(..., alias="is_php")
    is_js: bool = Field(..., alias="is_js")

class PredictionResponse(BaseModel):
    is_anomaly: bool
    confidence: float

# --- Inicialização do Aplicativo e Carregamento do Modelo ---
app = FastAPI()

MODEL_PATH = os.getenv("MODEL_PATH", "imunno_model.joblib")
model = None

@app.on_event("startup")
def load_model():
    """
    Função executada na inicialização do serviço para carregar o modelo de IA.
    Agora, ela lida graciosamente com a ausência do arquivo do modelo.
    """
    global model
    try:
        # Verifica se o arquivo do modelo existe ANTES de tentar carregá-lo.
        if os.path.exists(MODEL_PATH):
            model = joblib.load(MODEL_PATH)
            logger.info(f"Modelo de IA carregado com sucesso de '{MODEL_PATH}'")
        else:
            # Se o arquivo não existe, apenas registra um aviso. A aplicação continuará funcionando.
            logger.warning(f"AVISO: Arquivo do modelo '{MODEL_PATH}' não encontrado. O serviço iniciará sem capacidade de predição.")
            model = None
    except Exception as e:
        logger.error(f"ERRO CRÍTICO: Falha inesperada ao tentar carregar o modelo de IA: {e}")
        model = None

# --- Endpoints da API ---

@app.get("/health")
def health_check():
    """Endpoint de verificação de saúde."""
    if model is not None:
        return {"status": "ok", "model_loaded": True}
    return {"status": "warning", "model_loaded": False, "message": "O serviço está rodando, mas o modelo de IA não está carregado."}

@app.post("/predict", response_model=PredictionResponse)
def predict(event_data: EventData):
    """Endpoint principal para fazer previsões de anomalia."""
    # Se o modelo não foi carregado, retorna um erro 503 (Serviço Indisponível)
    # informando que a capacidade de predição não está ativa.
    if model is None:
        logger.error("Tentativa de predição falhou porque o modelo não está carregado.")
        raise HTTPException(status_code=503, detail="Serviço indisponível: Modelo de IA não carregado.")

    try:
        feature_order = ['threat_score', 'file_size', 'is_php', 'is_js']
        data_dict = event_data.dict()
        df = pd.DataFrame([data_dict])
        df = df[feature_order]

        prediction_result = model.predict(df.values)
        prediction_proba = model.predict_proba(df.values)

        is_anomaly = bool(prediction_result[0] == -1)
        confidence = float(prediction_proba.max())

        logger.info(f"Predição: Anomalia={is_anomaly}, Confiança={confidence:.4f}")

        return PredictionResponse(is_anomaly=is_anomaly, confidence=confidence)

    except Exception as e:
        logger.error(f"Erro durante a execução da predição: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Erro interno no processamento da predição: {e}")
