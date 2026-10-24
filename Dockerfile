# syntax=docker/dockerfile:1
FROM php:8.3-apache-trixie@sha256:0d46cb96775228313d3997c155f78227de13bf9972e0c736e653fb23aded79b2

LABEL org.opencontainers.image.title="EDL Manager" \
      org.opencontainers.image.description="Approval workflow and hosting for firewall External Dynamic Lists (IP, domain, and URL blocklists)" \
      org.opencontainers.image.source="https://github.com/darpanvedi0/EDL-Manager2.0" \
      org.opencontainers.image.licenses="MIT"

RUN cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
COPY docker/php/edl-manager.ini "$PHP_INI_DIR/conf.d/zz-edl-manager.ini"

COPY docker/apache/edl-manager.conf /etc/apache2/sites-available/edl-manager.conf
RUN a2enmod headers \
 && a2dissite 000-default \
 && a2disconf serve-cgi-bin other-vhosts-access-log \
 && a2ensite edl-manager \
 && echo 'Listen 8080' > /etc/apache2/ports.conf

COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/edl-manager-entrypoint
COPY --chmod=0755 docker/edl-users.php /usr/local/bin/edl-users

# Application code stays owned by root; the web server can only write to the
# two volumes. The base image leaves the web root world-writable.
COPY . /var/www/html/
RUN chown root:root /var/www/html \
 && chmod 0755 /var/www/html \
 && rm -rf /var/www/html/docker \
 && mkdir -p /usr/share/doc/edl-manager \
 && mv /var/www/html/LICENSE /usr/share/doc/edl-manager/ \
 && mkdir -p /var/www/html/data /var/www/html/edl-files \
 && chown www-data:www-data /var/www/html/data /var/www/html/edl-files \
 && chmod 0750 /var/www/html/data

USER www-data
EXPOSE 8080
VOLUME ["/var/www/html/data", "/var/www/html/edl-files"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS -o /dev/null http://127.0.0.1:8080/edl-files/ip_blocklist.txt || exit 1

ENTRYPOINT ["edl-manager-entrypoint"]
CMD ["apache2-foreground"]
