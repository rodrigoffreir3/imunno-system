# Estágio 1: Build - Usa a imagem completa do Go para compilar
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Compila a aplicação de forma estática para não ter dependências externas
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o imunno-collector .

# ---

# Estágio 2: Final - Usa uma imagem Alpine minúscula
FROM alpine:latest

WORKDIR /app

# Copia APENAS o executável compilado do estágio 'builder'
COPY --from=builder /app/imunno-collector .

# Expõe a porta que o collector usa
EXPOSE 8080

# O comando para rodar o executável
CMD ["./imunno-collector"]