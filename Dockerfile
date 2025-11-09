# Use Go official image
FROM golang:1.24-alpine

# Set working dir
WORKDIR /app

# Copy go.mod and go.sum for caching dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the app
COPY . .

# Build the app
RUN go build -o main ./cmd/server/

# Expose port
EXPOSE 8080

# Run the app
CMD ["./main"]
