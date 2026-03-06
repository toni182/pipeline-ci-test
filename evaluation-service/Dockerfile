# Etapa 1: Build do Go
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copia arquivos de dependências
COPY go.mod go.sum ./
RUN go mod download

# Copia todo o código
COPY . .

# Compila o binário
RUN go build -o evaluation-service .

# Etapa 2: Container final mais leve
FROM alpine:latest
WORKDIR /app

# Copia o binário e o .env
COPY --from=builder /app/evaluation-service .
COPY env .

EXPOSE 8004

# Comando padrão ao iniciar o container
CMD ["./evaluation-service"]
