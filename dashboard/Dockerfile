FROM nginx:alpine
COPY index.html /usr/share/nginx/html/
COPY style.css /usr/share/nginx/html/
COPY script.js /usr/share/nginx/html/
RUN mkdir -p /usr/share/nginx/html/logs && chmod 777 /usr/share/nginx/html/logs
