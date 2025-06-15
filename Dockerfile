
FROM golang:1.22
WORKDIR /app

# Install openssl for certificates
RUN apt-get update && apt-get install -y openssl

# Copy go mod files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Generate certificates (FIXED - was using cert.pem for both)
RUN openssl req -x509 -newkey rsa:4096 -sha256 -nodes \
      -keyout key.pem \
      -out cert.pem \
      -subj "/CN=localhost" \
      -days 365

# Build the application
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bbrf_server .

# Make executable
RUN chmod +x bbrf_server

# Expose port
EXPOSE 8443

# Run the server
CMD ["./bbrf_server"]
