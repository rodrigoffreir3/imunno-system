# Dockerfile do imunno-collector
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copia os arquivos Go
COPY . .

# Baixa dependências
RUN go mod tidy

# Compila o binário
RUN go build -o imunno-collector main.go

# Imagem final minimalista
FROM alpine:3.18

WORKDIR /app

# Copia o binário do builder
COPY --from=builder /app/imunno-collector .

# Define o executável padrão
CMD ["./imunno-collector"]
