FROM alpine:latest

# Install network exploration tools
RUN apk update && apk add --no-cache nmap nmap-scripts iproute2 curl

# Keep the container running idle
CMD ["tail", "-f", "/dev/null"]
