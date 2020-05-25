FROM  php:7-apache
MAINTAINER mumtaz_ahmad@mentor.com
RUN apt-get update && apt-get install -y git zip unzip
RUN pecl install mongodb
RUN echo extension=/usr/local/lib/php/extensions/no-debug-non-zts-20190902/mongodb.so >> /usr/local/etc/php/conf.d/docker-php-ext-sodium.ini	
RUN curl -s https://getcomposer.org/installer | php
RUN mv composer.phar /usr/local/bin/composer
RUN git clone https://github.com/mahmad2504/svmsync.git
RUN cd svmsync && composer install
RUN echo '20200525' >/dev/null && cd svmsync && git fetch --all && git reset --hard origin/master
RUN cd svmsync && php index.php