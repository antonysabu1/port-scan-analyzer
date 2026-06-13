FROM alpine:latest

# Install some basic services to simulate a target
RUN apk update && apk add --no-cache nginx dropbear

# Create run directory for nginx
RUN mkdir -p /run/nginx

# Start nginx in the foreground
CMD ["nginx", "-g", "daemon off;"]
