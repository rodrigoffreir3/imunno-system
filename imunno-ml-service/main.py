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

# Caminho para o modelo de IA. Usando o nome correto que você apontou.
MODEL_PATH = os.getenv("MODEL_PATH", "imunno_model.joblib")
model = None

@app.on_event("startup")
def load_model():
    """
    Função executada na inicialização do serviço para carregar o modelo de IA.
    """
    global model
    try:
        model = joblib.load(MODEL_PATH)
        logger.info(f"Modelo de IA carregado com sucesso de '{MODEL_PATH}'")
    except FileNotFoundError:
        logger.error(f"ERRO CRÍTICO: Arquivo do modelo não encontrado em '{MODEL_PATH}'")
        model = None
    except Exception as e:
        logger.error(f"ERRO CRÍTICO: Falha ao carregar o modelo de IA: {e}")
        model = None

# --- Endpoints da API ---

@app.get("/health")
def health_check():
    """Endpoint de verificação de saúde."""
    if model is not None:
        return {"status": "ok", "model_loaded": True}
    return {"status": "error", "model_loaded": False, "message": "Modelo de IA não pôde ser carregado."}

@app.post("/predict", response_model=PredictionResponse)
def predict(event_data: EventData):
    """Endpoint principal para fazer previsões de anomalia."""
    if model is None:
        logger.error("Tentativa de predição falhou porque o modelo não está carregado.")
        raise HTTPException(status_code=503, detail="Serviço indisponível: Modelo de IA não carregado.")

    try:
        # A ordem das features DEVE ser a mesma usada no notebook de treinamento.
        feature_order = ['threat_score', 'file_size', 'is_php', 'is_js']

        # Converte o objeto Pydantic para um dicionário.
        data_dict = event_data.dict()

        # Cria um DataFrame do Pandas, garantindo a ordem correta das colunas.
        df = pd.DataFrame([data_dict])
        df = df[feature_order]

        logger.info(f"DataFrame criado para predição: \n{df.to_string()}")

        # Realiza a predição.
        prediction_result = model.predict(df.values)
        prediction_proba = model.predict_proba(df.values)

        # O resultado de predict() é -1 para anomalia e 1 para normal.
        is_anomaly = bool(prediction_result[0] == -1)

        # A 'confiança' é a maior probabilidade entre as classes.
        confidence = float(prediction_proba.max())

        logger.info(f"Predição: Anomalia={is_anomaly}, Confiança={confidence:.4f}")

        return PredictionResponse(is_anomaly=is_anomaly, confidence=confidence)

    except Exception as e:
        logger.error(f"Erro durante a execução da predição: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Erro interno no processamento da predição: {e}")
