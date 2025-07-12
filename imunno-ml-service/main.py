# Arquivo: imunno-ml-service/main.py (Com o carregamento do modelo correto)
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List
import logging
import joblib
import pandas as pd # type: ignore
import json

# --- CONFIGURAÇÃO E CARREGAMENTO DO MODELO ---
logging.basicConfig(level=logging.INFO)
app = FastAPI()

try:
    # >>>>>>>>>>>>>>>> CORREÇÃO IMPORTANTE <<<<<<<<<<<<<<<<
    # Carregando o arquivo de modelo correto que nós treinamos.
    model = joblib.load("imunno_classifier.joblib")
    logging.info("Modelo de classificação de IA 'imunno_classifier.joblib' carregado com sucesso!")
except FileNotFoundError:
    logging.error("Arquivo do modelo 'imunno_classifier.joblib' não encontrado! Certifique-se de que ele está na mesma pasta.")
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
    return {"status": "Imunno ML Service (Classifier) is running", "model_loaded": model is not None}

@app.post("/analyze")
def analyze_event(event: EventData):
    if model is None:
        raise HTTPException(status_code=500, detail="Modelo de IA não está carregado.")

    logging.info(f"Analisando evento do agente {event.agent_id} com o modelo classificador...")

    if event.event_type != "FILE_EVENT":
        return {"prediction": "benign", "prediction_label": 0, "message": "Modelo atual só analisa eventos de arquivo."}

    # 1. ENGENHARIA DE FEATURES
    threat_score = event.details.get("threat_score", 0)
    analysis_findings_list = event.details.get("analysis_findings", [])
    num_findings = len(analysis_findings_list)
    file_path = event.details.get("file_path", "")
    is_php = 1 if file_path.endswith('.php') else 0

    current_features = pd.DataFrame(
        [[threat_score, num_findings, is_php]], 
        columns=['threat_score', 'num_findings', 'is_php']
    )

    # 2. INFERÊNCIA
    prediction_label = model.predict(current_features)[0]
    prediction_text = "malicious" if prediction_label == 1 else "benign"

    logging.info(f"Previsão do modelo: {prediction_text.upper()} (Rótulo: {prediction_label})")

    # 3. RETORNO
    return {
        "prediction": prediction_text,
        "prediction_label": int(prediction_label),
        "threat_score_input": threat_score,
        "message": "Análise de classificação concluída."
    }