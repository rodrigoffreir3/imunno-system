# Arquivo: imunno-ml-service/main.py

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
import logging
import joblib
import pandas as pd

# --- CONFIGURAÇÃO E CARREGAMENTO DO MODELO ---

logging.basicConfig(level=logging.INFO)
app = FastAPI()

# Carregamos o nosso "cérebro" treinado na inicialização do serviço.
try:
    model = joblib.load("imunno_model.joblib")
    logging.info("Modelo de IA carregado com sucesso!")
except FileNotFoundError:
    logging.error("Arquivo do modelo 'imunno_model.joblib' não encontrado!")
    model = None

# --- DEFINIÇÃO DOS DADOS DE ENTRADA ---

class EventData(BaseModel):
    agent_id: str
    hostname: str
    event_type: str
    details: Dict[str, Any]

# --- ENDPOINTS DA API ---

@app.get("/")
def read_root():
    return {"status": "Imunno ML Service is running", "model_loaded": model is not None}

@app.post("/analyze")
def analyze_event(event: EventData):
    """
    Recebe um evento, o prepara, e usa o modelo de IA carregado para
    detectar se ele é uma anomalia.
    """
    if model is None:
        raise HTTPException(status_code=500, detail="Modelo de IA não está carregado.")

    logging.info(f"Analisando evento do agente {event.agent_id} com o modelo de IA...")

    # 1. PREPARAÇÃO DOS DADOS (Feature Engineering)
    # Precisamos criar os dados para o modelo exatamente no mesmo formato que usamos para o treinamento.
    # Por enquanto, nosso modelo só foi treinado com 'threat_score'.
    
    threat_score = event.details.get("threat_score", 0) # Pega o score, ou usa 0 se não existir (ex: para eventos de processo)
    
    # Cria um DataFrame do Pandas com os dados do evento atual.
    # O nome da coluna ['threat_score'] deve ser o mesmo usado no treinamento.
    current_features = pd.DataFrame([[threat_score]], columns=['threat_score'])

    # 2. INFERÊNCIA (A Previsão)
    # Usamos o método .predict() para que o modelo nos diga se é uma anomalia.
    # Ele retorna -1 para anomalias (outliers) e 1 para eventos normais (inliers).
    prediction = model.predict(current_features)
    
    is_anomaly = True if prediction[0] == -1 else False

    logging.info(f"Previsão do modelo: {'Anomalia Detectada' if is_anomaly else 'Comportamento Normal'}")

    # 3. RETORNO DA ANÁLISE
    return {
        "is_anomaly": is_anomaly,
        "threat_score_input": threat_score,
        "message": "Análise de anomalia concluída."
    }