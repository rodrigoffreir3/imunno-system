# Arquivo: imunno-collector/Dockerfile

# --- Estágio 1: Builder ---
FROM golang:1.24-alpine AS builder
WORKDIR /build-src
RUN apk add --no-cache git ca-certificates
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -v -o /imunno-collector .

# --- Estágio 2: Final ---
FROM alpine:latest
WORKDIR /app
COPY --from=builder /imunno-collector /app/imunno-collector

# Copiar arquivos estáticos do dashboard, se existirem
COPY static /app/static

EXPOSE 8080
CMD ["/app/imunno-collector"]
