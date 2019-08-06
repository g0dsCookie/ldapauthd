FROM alpine:3.9

RUN set -eu \
 && cecho() { echo "\033[1;32m$1\033[0m"; } \
 && cecho "###### INSTALLING DEPENDENCIES ######" \
 && apk --no-cache add --virtual ldapauthd-deps \
        python3 py2-pip ca-certificates bash \
 && apk --no-cache add --virtual build-deps \
        gcc g++ libc-dev python3-dev \
 && pip3 --no-cache-dir install --upgrade pip \
 && pip3 --no-cache-dir install ldap3 pymemcache murmurhash3 \
 && apk del build-deps

ENV LDAPAUTHD_LOGLEVEL=INFO \
    LDAPAUTHD_USER=nobody \
    LDAPAUTHD_IP=0.0.0.0 \
    LDAPAUTHD_PORT=80 \
    LDAPAUTHD_REALM=Authorization\ required \
    LDAPAUTHD_SESSION_STORAGE=memcached \
    LDAPAUTHD_SESSION_DOMAIN= \
    LDAPAUTHD_SESSION_HOST=sessiondb:11211 \
    LDAPAUTHD_SESSION_TTL=900 \
    LDAPAUTHD_SESSION_RETRY=1 \
    LDAP_LOGLEVEL=ERROR \
    LDAP_BASEDN=ou=Company,dc=example,dc=org \
    LDAP_BINDDN=cn=bind user,dc=example,dc=org \
    LDAP_BINDPW=password \
    LDAP_ATTRIBUTES='{"cn": "X-Forwarded-FullName", "mail": "X-Forwarded-Email", "sAMAccountName": "X-Forwarded-User"}' \
    LDAP_ROLEHEADER=X-Forwarded-Role \
    LDAP_ALLOWEDUSERS= \
    LDAP_ALLOWEDGROUPS= \
    LDAP_BACKENDS=

ARG MAINTAINER="g0dscookie@cookieprojects.de"
ARG DESCRIPTION="Simple HTTP ldap auth daemon"
ARG VERSION

LABEL maintainer="${MAINTAINER}" \
      version="${VERSION}" \
      description="${DESCRIPTION}"

COPY --chown=0:0 ldapauthd.py /usr/sbin/ldapauthd
COPY --chown=0:0 entrypoint.sh /entrypoint

EXPOSE 80

VOLUME [ "/usr/local/share/ca-certificates" ]

USER root
ENTRYPOINT [ "/entrypoint", "/usr/sbin/ldapauthd" ]
CMD []
