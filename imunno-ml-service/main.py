# Arquivo: imunno-ml-service/main.py (Corrigido)

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging

# Configuração do logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# Define o modelo de dados para a requisição de predição
class PredictionRequest(BaseModel):
    threat_score: int
    file_size: int
    is_php: bool
    is_js: bool

# Carrega o modelo de IA treinado
try:
    model = joblib.load('imunno_model.joblib')
    log.info("Modelo de IA carregado com sucesso de 'imunno_model.joblib'")
except FileNotFoundError:
    log.warning("AVISO: Arquivo do modelo 'imunno_model.joblib' não encontrado. O serviço iniciará sem capacidade de predição.")
    model = None

app = FastAPI()

@app.get("/health")
def health_check():
    """Verifica a saúde do serviço."""
    return {"status": "ok", "model_loaded": model is not None}

@app.post("/predict")
def predict(request: PredictionRequest):
    """Executa a predição com base nos dados recebidos."""
    if model is None:
        raise HTTPException(status_code=503, detail="Modelo de IA não está carregado.")

    try:
        # Cria um DataFrame do pandas com os dados da requisição
        # Os nomes das colunas devem corresponder aos usados no treinamento
        feature_names = ['threat_score', 'file_size', 'is_php', 'is_js']
        df = pd.DataFrame([request.dict()], columns=feature_names)

        # --- CORREÇÃO APLICADA AQUI ---
        # O modelo IsolationForest não tem 'predict_proba'.
        # Usamos 'predict' para obter a classificação (-1 para anomalia, 1 para normal)
        # e 'decision_function' para obter um score de confiança.

        prediction = model.predict(df.values)
        score = model.decision_function(df.values)

        # Converte o resultado para um formato mais legível
        # Se a predição for -1, é uma anomalia.
        is_anomaly = bool(prediction[0] == -1)
        
        # O score de 'decision_function' é negativo para anomalias.
        # Podemos usar uma lógica para convertê-lo em uma "confiança" de 0 a 1,
        # mas por simplicidade, vamos retornar o score bruto.
        confidence = float(score[0])

        log.info(f"Predição executada: Anomalia={is_anomaly}, Score={confidence:.4f}")

        return {
            "is_anomaly": is_anomaly,
            "confidence": confidence
        }

    except Exception as e:
        log.error(f"Erro durante a execução da predição: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Erro interno no processamento da predição: {e}")