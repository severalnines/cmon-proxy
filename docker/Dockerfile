FROM golang:1.22-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git cmake g++ rpm

COPY . .

# Build both binaries
RUN go build -o ccmgr ./main.go
RUN cd ccmgradm && go build -o ccmgradm .

# Get frontend files from the frontend image
FROM europe-docker.pkg.dev/severalnines-dev/clustercontrol/frontend:latest AS frontend

FROM alpine:latest

WORKDIR /app

# Copy binaries and make them executable (fix the path)
COPY --from=builder /app/ccmgr /usr/local/bin/ccmgr
COPY --from=builder /app/ccmgradm/ccmgradm /usr/local/bin/ccmgradm
RUN chmod +x /usr/local/bin/ccmgr /usr/local/bin/ccmgradm

# Copy frontend files from the frontend image
COPY --from=frontend /app /var/www/frontend

# Create entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create necessary directories
RUN mkdir -p /usr/share/ccmgr

ENV GIN_MODE=release

EXPOSE 19051

ENTRYPOINT ["/entrypoint.sh"]
