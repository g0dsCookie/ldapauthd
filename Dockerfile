FROM alpine:3.9

ARG MAINTAINER="g0dscookie@cookieprojects.de"
ARG DESCRIPTION="Simple HTTP ldap auth daemon"

ARG VERSION

LABEL maintainer="${MAINTAINER}" \
      version="${VERSION}" \
      description="${DESCRIPTION}"

RUN set -eu \
 && cecho() { echo "\033[1;32m$1\033[0m"; } \
 && cecho "###### INSTALLING DEPENDENCIES ######" \
 && apk --no-cache add --virtual ldapauthd-deps python3 py3-pyldap ca-certificates bash

COPY --chown=0:0 ldapauthd.py /usr/sbin/ldapauthd
COPY --chown=0:0 entrypoint.sh /entrypoint

ENV LDAPAUTHD_LOGLEVEL=INFO \
    LDAPAUTHD_USER=nobody \
    LDAPAUTHD_UMASK=755 \
    LDAPAUTHD_IP=0.0.0.0 \
    LDAPAUTHD_PORT=80 \
    LDAP_HOST=dc01.example.org \
    LDAP_PORT=636 \
    LDAP_SSL=True \
    LDAP_SSL_VALIDATE=True \
    LDAP_BASEDN=ou=Company,dc=example,dc=org \
    LDAP_BINDDN=cn=bind user,dc=example,dc=org \
    LDAP_BINDPW=password

EXPOSE 8080

VOLUME [ "/usr/local/share/ca-certificates" ]

USER root
ENTRYPOINT [ "/entrypoint", "/usr/sbin/ldapauthd" ]
CMD []
