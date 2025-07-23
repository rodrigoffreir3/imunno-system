# Estágio 1: Build - Usa a imagem completa do Go para compilar
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

# Copia todo o código-fonte, incluindo a pasta 'static'
COPY . .

# Compila a aplicação de forma estática
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o imunno-collector .

# ---

# Estágio 2: Final - A imagem leve que será executada
FROM alpine:latest

WORKDIR /app

# --- CORREÇÃO APLICADA AQUI ---
# Copia o executável E TAMBÉM a pasta 'static' do estágio de build
COPY --from=builder /app/imunno-collector .
COPY --from=builder /app/static ./static

# Expõe a porta que o collector usa
EXPOSE 8080

# O comando para rodar o executável
CMD ["./imunno-collector"]