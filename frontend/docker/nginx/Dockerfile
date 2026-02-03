FROM nginx:1.27-alpine

# App files must exist here so nginx can serve public/ and reference index.php path
WORKDIR /var/www/html
COPY . /var/www/html

COPY docker/nginx/default.conf /etc/nginx/conf.d/default.conf

EXPOSE 8080