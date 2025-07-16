# Arquivo: imunno-agent/Dockerfile
FROM golang:1.24-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git ca-certificates audit
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -v -o /app/imunno-agent .

FROM alpine:latest
WORKDIR /app
RUN apk add --no-cache audit shadow
COPY --from=builder /app/imunno-agent .
COPY entrypoint.sh .

# Garantir que o log exista com permissões adequadas
RUN mkdir -p /var/log/audit && touch /var/log/audit/audit.log && chmod 640 /var/log/audit/audit.log

RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]
