# Estágio 1: O Construtor (Builder)
# Usamos uma imagem completa do Debian para ter acesso às ferramentas de compilação.
FROM python:3.11-slim-bookworm as builder

# Instala as ferramentas de compilação C++ essenciais dentro do contêiner.
RUN apt-get update && apt-get install -y build-essential

# Define o diretório de trabalho
WORKDIR /app

# Copia apenas o arquivo de requisitos para aproveitar o cache do Docker.
COPY requirements.txt .

# Instala as dependências. O pip vai usar o compilador que acabamos de instalar.
RUN pip install --no-cache-dir -r requirements.txt


# Estágio 2: A Imagem Final
# Começamos de novo com uma imagem base leve e limpa.
FROM python:3.11-slim-bookworm

# Define o diretório de trabalho
WORKDIR /app

# Copia as bibliotecas já compiladas e prontas do estágio 'builder'.
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Agora, copia o código da sua aplicação.
COPY . .

# Expõe a porta que a sua aplicação FastAPI/Uvicorn usa.
EXPOSE 8000

# O comando para iniciar o seu serviço de IA.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]