# Estágio 1: Builder - Instala as dependências em um ambiente temporário
FROM python:3.11-slim AS builder

WORKDIR /app

# Instala as dependências de build necessárias para alguns pacotes Python
RUN apt-get update && apt-get install -y --no-install-recommends build-essential

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---

# Estágio 2: Final - A imagem que realmente vamos usar
FROM python:3.11-slim

WORKDIR /app

# --- CORREÇÃO APLICADA AQUI ---
# Copia as bibliotecas E TAMBÉM os executáveis (como uvicorn) do estágio 'builder'
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Agora, copia o código da sua aplicação
COPY . .

EXPOSE 5000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]