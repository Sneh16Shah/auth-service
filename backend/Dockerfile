# Stage 1: Build the Go binary
# Use a specific, stable version of the official Go image for the build stage.
FROM golang:1.24-bookworm AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to leverage Docker's cache.
# If these files haven't changed, the `go mod download` step can be skipped in subsequent builds.
COPY go.mod ./
# COPY go.sum ./

RUN go mod download

# Copy the rest of the application source code
COPY . .

# Expose port 8080 to allow external access to the application
EXPOSE 8080

# Build the Go application.
# The -o flag specifies the output binary name.
# In this case, we're creating a binary named "auth-service".
RUN go build -o auth-service .

#Command to run the application
# Use "go run ." for development so that file changes (via volumes) are picked up immediately
# CMD ["/app/auth-service"]
CMD ["go", "run", "."]