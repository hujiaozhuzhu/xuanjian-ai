FROM php:7.4-apache

# 不安装扩展，仅启用rewrite模块
RUN a2enmod rewrite

COPY . /var/www/html

RUN chown -R www-data:www-data /var/www/html && \
    chmod -R 755 /var/www/html

EXPOSE 80
