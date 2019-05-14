FROM alpine:3.9

ARG MAINTAINER="g0dscookie@cookieprojects.de"
ARG DESCRIPTION="Simple HTTP ldap auth daemon"

RUN set -eu \
 && cecho() { echo "\033[1;32m$1\033[0m"; } \
 && cecho "###### INSTALLING DEPENDENCIES ######" \
 && apk --no-cache add --virtual ldapauthd-deps python3 py2-pip ca-certificates bash \
 && pip3 --no-cache-dir install --upgrade pip \
 && pip3 --no-cache-dir install ldap3

ARG VERSION

LABEL maintainer="${MAINTAINER}" \
      version="${VERSION}" \
      description="${DESCRIPTION}"

COPY --chown=0:0 ldapauthd.py /usr/sbin/ldapauthd
COPY --chown=0:0 entrypoint.sh /entrypoint

ENV LDAPAUTHD_LOGLEVEL=INFO \
    LDAPAUTHD_USER=nobody \
    LDAPAUTHD_UMASK=755 \
    LDAPAUTHD_IP=0.0.0.0 \
    LDAPAUTHD_PORT=80 \
    LDAPAUTHD_REALM=Authorization\ required \
    LDAP_LOGLEVEL=ERROR \
    LDAP_BASEDN=ou=Company,dc=example,dc=org \
    LDAP_BINDDN=cn=bind user,dc=example,dc=org \
    LDAP_BINDPW=password \
    LDAP_ATTRIBUTES='{"cn": "X-Forwarded-FullName", "mail": "X-Forwarded-Email", "sAMAccountName": "X-Forwarded-User"}' \
    LDAP_ALLOWEDUSERS= \
    LDAP_ALLOWEDGROUPS= \
    LDAP_ROLEHEADER=X-Forwarded-Role \
    LDAP_BACKENDS=

EXPOSE 80

VOLUME [ "/usr/local/share/ca-certificates" ]

USER root
ENTRYPOINT [ "/entrypoint", "/usr/sbin/ldapauthd" ]
CMD []
