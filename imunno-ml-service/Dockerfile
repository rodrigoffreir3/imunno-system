# Arquivo definitivo: imunno-ml-service/Dockerfile

FROM python:3.13-slim
WORKDIR /app

RUN apt-get update && apt-get install -y curl --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o resto da nossa aplicação: main.py e o nosso cérebro de IA, model.joblib.
COPY . .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]