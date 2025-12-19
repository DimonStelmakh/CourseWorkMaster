FROM nginx:alpine

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Copy static files
COPY static /usr/share/nginx/html/static
COPY templates /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
