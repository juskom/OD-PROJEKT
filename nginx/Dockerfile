FROM nginx:1.22.1


RUN apt-get update && apt-get install -y nginx-extras

COPY default.conf /etc/nginx/conf.d/default.conf

RUN mkdir -p /etc/nginx/ssl

COPY ./ssl/signed.crt /etc/nginx/ssl/signed.crt
COPY ./ssl/signed.key /etc/nginx/ssl/signed.key

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]