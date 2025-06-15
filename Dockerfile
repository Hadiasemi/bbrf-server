FROM golang:1.20

WORKDIR /app

# Copy Go source
COPY . .

# Install OpenSSL
RUN apt-get update && apt-get install -y openssl

# Generate self-signed cert if not exists
RUN mkdir -p certs && \
    [ ! -f certs/cert.pem ] && [ ! -f certs/key.pem ] && \
    openssl req -x509 -newkey rsa:4096 -sha256 -nodes \
      -keyout certs/key.pem \
      -out certs/cert.pem \
      -subj "/CN=localhost" \
      -days 365

# Build Go app
RUN go get ./...
RUN go build -o bbrf_server server.go

CMD ["./bbrf_server"]

