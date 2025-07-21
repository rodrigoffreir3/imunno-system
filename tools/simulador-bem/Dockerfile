# Arquivo: tools/simulador-bem/Dockerfile (Corrigido)
FROM golang:1.24-alpine

WORKDIR /app

# Copia os arquivos de módulo primeiro para otimizar o cache do Docker
COPY go.mod ./

# Baixa as dependências (se houver alguma)
RUN go mod tidy

# Copia o restante do código (simulador_bem.go)
COPY . .

# Compila o simulador benigno
RUN go build -o simulador_bem .

# Define o comando padrão para executar o simulador
CMD ["./simulador_bem"]