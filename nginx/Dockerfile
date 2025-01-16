FROM nginx:latest

#COPY ./ssl /etc/ssl/

COPY default.conf /etc/nginx/conf.d/default.conf

#COPY ./static /usr/share/nginx/html

RUN mkdir -p /etc/nginx/ssl

COPY ./ssl/signed.crt /etc/nginx/ssl/signed.crt
COPY ./ssl/signed.key /etc/nginx/ssl/signed.key

# Expose ports 80 and 443
EXPOSE 80 443

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]