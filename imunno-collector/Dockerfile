# Arquivo: imunno-collector/Dockerfile (Versão Definitiva)

# --- Estágio 1: Builder ---
# Compila nosso programa.
FROM golang:1.24-alpine AS builder
WORKDIR /build-src
RUN apk add --no-cache git ca-certificates
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -v -o /imunno-collector .

# --- Estágio 2: Final ---
# Cria a imagem final e leve.
FROM alpine:latest

# Copia o programa compilado para a raiz do sistema de arquivos.
COPY --from=builder /imunno-collector /imunno-collector

# Copia os arquivos do nosso dashboard para uma pasta /static.
COPY static /static

# Expõe a porta que nosso servidor Go usará.
EXPOSE 8080

# Comando para iniciar nosso programa.
CMD ["/imunno-collector"]