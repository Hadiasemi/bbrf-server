FROM golang:1.22

WORKDIR /app

# Install openssl for certificates
RUN apt-get update && apt-get install -y openssl

# Copy go mod files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Generate certificates
RUN mkdir -p certs && \
    openssl req -x509 -newkey rsa:4096 -sha256 -nodes \
      -keyout certs/key.pem \
      -out certs/cert.pem \
      -subj "/CN=localhost" \
      -days 365

# Tidy modules and build
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bbrf_server .

# Make sure the executable has proper permissions
RUN chmod +x bbrf_server

# Verify it exists
RUN ls -la bbrf_server

# Expose port
EXPOSE 8443

# Run the server
CMD ["./bbrf_server"]
