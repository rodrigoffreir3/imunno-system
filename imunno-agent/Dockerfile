# Arquivo: imunno-agent/Dockerfile (Versão final)
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
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]