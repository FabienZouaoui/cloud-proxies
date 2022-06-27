FROM		alpine:latest
MAINTAINER	Fabien Zouaoui <fzo@sirdata.fr>
LABEL		Description="Base alpine with haproxy and stuff to forward requests to socks proxy instances"

ENV BOTO3_VERS 1.7.19

RUN apk update && \
    apk add ca-certificates openssl haproxy python3 groff less openssh-client py3-jinja2 tini py3-pip && \
    update-ca-certificates && \
    rm -f /var/cache/apk/*

RUN pip install --upgrade pip
RUN pip install --no-cache-dir awscli boto3
RUN pip install --no-cache-dir requests
RUN pip install --no-cache-dir pproxy

RUN mkdir /templates
COPY manage-proxies.py /manage-proxies.py
COPY manage-http-proxies.py /manage-http-proxies.py
COPY haproxy.cfg.tmpl /templates/haproxy.cfg.tmpl
COPY haproxy_http.cfg.tmpl /templates/haproxy_http.cfg.tmpl

# Doesn't work as-is and haproxy drops privileges anyway
#USER daemon

ENTRYPOINT ["/bin/sh"]
