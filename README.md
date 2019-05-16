# ldapauthd

This is a simple HTTP server which allows you to authenticate against ldap with a HTTP GET request. This daemon is designed to run behind a reverse proxy (haproxy, nginx, apache2, ...).

- [ldapauthd](#ldapauthd)
- [Usage](#usage)
  - [Examples](#examples)
    - [Curl](#curl)
    - [Traefik](#traefik)
- [Installation](#installation)
  - [Local](#local)
  - [Docker](#docker)
- [Configuration](#configuration)
  - [Examples](#examples-1)
    - [LDAP_ALLOWEDUSERS](#ldapallowedusers)
    - [LDAP_ALLOWEDGROUPS](#ldapallowedgroups)
- [Special Thanks](#special-thanks)

# Usage

To authenticate against this daemon you only need to fire a GET request with base64 encoded **Authentication** HTTP header.

## Examples

### Curl

`$ curl -v --user 'username:password' localhost`

### Traefik

```yaml
version: "3.7"
services:
  traefik:
    image: traefik
    network:
      - internal
    [...]
  auth:
    image: g0dscookie/ldapauthd
    network:
      - internal
    [...]
  backend:
    image: mybackend
    network:
      - internal
    deploy:
      labels:
        traefik.enable: "true"
        traefik.frontend.auth.forward.address: "http://auth"
        traefik.frontend.auth.forward.authResponseHeaders: "X-Forwarded-FullName,X-Forwarded-User,X-Forwarded-Email,X-Forwarded-Role"
```

# Installation

## Local

```sh
git clone https://github.com/g0dsCookie/ldapauthd.git
cd ldapauthd
pip install -r requirements.txt
```

Now you may run with `./ldapauthd.py` but I highly recommend reading [Configuration](#configuration).

## Docker

Docker image **g0dscookie/ldapauthd** is available. See **docker-compose.yml** for configuration and usage of this container.

# Configuration

Configuration for this daemon is read from the current environment. Available configuration parameters are:

| Environment Variable        | Description                                      | Default                |
| --------------------------- | ------------------------------------------------ | ---------------------- |
| LDAPAUTHD_IP                | IP address the daemon should listen on.          | 0.0.0.0                |
| LDAPAUTHD_PORT              | Port the daemon should listen on.                | 80                     |
| LDAPAUTHD_LOGLEVEL          | Loglevel the daemon should run on.               | INFO                   |
| LDAPAUTHD_USER              | User the daemon should be run with.              | nobody                 |
| LDAPAUTHD_REALM             | String to set in WWW-Authenticate.               | Authorization required |
| LDAPAUTHD_SESSION_STORAGE   | Choose session storage backend. Available: memcached | memcached          |
| LDAPAUTHD_SESSION_HOST      | Host address of your session storage.            | localhost:11211        |
| LDAPAUTHD_SESSION_TTL       | Maximum TTL for sessions in seconds.             | 900                    |
| LDAP_LOGLEVEL               | https://ldap3.readthedocs.io/logging.html#logging-detail-level | ERROR    |
| LDAP_ATTRIBUTES             | Attributes to get from ldap and report to client | {"cn": "X-Forwarded-FullName", "mail": "X-Forwarded-Email", "sAMAccountName": "X-Forwarded-User"} |
| LDAP_ROLEHEADER             | The header name where the associated role should be stored | X-Forwarded-Role |
| LDAP_ALLOWEDUSERS           | Allow specific users. Will be matched with given username |               |
| LDAP_ALLOWEDGROUPS          | Allow specific groups. Will be matched with full group dn |               |
| LDAP_BASEDN                 | Base DN every search request will be based on.   |                        |
| LDAP_BINDDN                 | Bind user to use for querying your ldap server.  |                        |
| LDAP_BINDPW                 | Bind users password.                             |                        |
| LDAP_BACKENDS               | Comma seperated list of ldap backend names.      |                        |
| LDAP_\<NAME\>_HOST          | Hostname of your domain controller.              |                        |
| LDAP_\<NAME\>_PORT          | Port on your domain controller to connect to.    | 636                    |
| LDAP_\<NAME\>_SSL           | Use SSL for ldap connection.                     | True                   |
| LDAP_\<NAME\>_SSL_VALIDATE  | Verify remote SSL certificate.                   | True                   |

## Examples

### LDAP_ALLOWEDUSERS

Used to allow specific users and assign specific roles to them. Always overwrites **LDAP_ALLOWEDGROUPS**.

Users are matched case-insensitive.

`LDAP_ALLOWEDUSERS={"username": "admin", "foobar": "nobody"}`

### LDAP_ALLOWEDGROUPS

Used to allow groups and assign appropriate role to the user. May be overwritten by **LDAP_ALLOWEDUSERS**.

First matched group will be used to allow access and assign the role.

Groups are matched case-insensitive.

`LDAP_ALLOWEDGROUPS={"cn=admins,dc=example,dc=org": "admin", "cn=domain users,dc=example,dc=org": "users"}`
