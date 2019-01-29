#!/bin/sh

[[ "${LDAP_BINDPW:-}" == "/"* ]] &&
    export LDAP_BINDPW=$(<${LDAP_BINDPW})

update-ca-certificates

exec "$@"