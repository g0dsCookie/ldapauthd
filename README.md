# ldapauthd

This is a simple HTTP server which allows you to authenticate against ldap with a HTTP GET request. This daemon is designed to run behind a reverse proxy (haproxy, nginx, apache2, ...).

- [ldapauthd](#ldapauthd)
  - [Usage](#usage)
    - [Installation](#installation)
      - [Local](#local)
      - [Docker](#docker)
    - [Configuration](#configuration)
      - [Curl example](#curl-example)
- [Special Thanks](#special-thanks)

## Usage

To authenticate against this daemon you only need to fire a GET request with base64 encoded **Authentication** HTTP header.

### Installation

#### Local

```sh
git clone https://github.com/g0dsCookie/ldapauthd.git
cd ldapauthd
pip install -r requirements.txt
```

Now you may run with `./ldapauthd.py` but I highly recommend reading [Configuration](#configuration).

#### Docker

Docker image **g0dscookie/ldapauthd** is available. See **docker-compose.yml** for configuration and usage of this container.

### Configuration

Configuration for this daemon is read from the current environment. Available configuration parameters are:

| Environment Variable        | Description                                     | Default                |
| --------------------------- | ----------------------------------------------- | :--------------------: |
| LDAPAUTHD_LOGLEVEL          | Loglevel the daemon should run on.              | INFO                   |
| LDAPAUTHD_USER              | User the daemon should be run with.             | nobody                 |
| LDAPAUTHD_UMASK             | Umask the daemon should run with.               | 755                    |
| LDAPAUTHD_IP                | IP address the daemon should listen on.         | 0.0.0.0                |
| LDAPAUTHD_PORT              | Port the daemon should listen on.               | 80                     |
| LDAPAUTHD_REALM             | String to set in WWW-Authenticate               | Authorization required |
| LDAP_BASEDN                 | Base DN every search request will be based on.  |                        |
| LDAP_BINDDN                 | Bind user to use for querying your ldap server. |                        |
| LDAP_BINDPW                 | Bind users password.                            |                        |
| LDAP_BACKENDS               | Comma seperated list of ldap backend names.     |                        |
| LDAP_\<NAME\>_HOST          | Hostname of your domain controller.             |                        |
| LDAP_\<NAME\>_PORT          | Port on your domain controller to connect to.   | 636                    |
| LDAP_\<NAME\>_SSL           | Use SSL for ldap connection.                    | True                   |
| LDAP_\<NAME\>_SSL_VALIDATE  | Verify remote SSL certificate.                  | True                   |

#### Curl example

`$ curl -v --user 'username:password' localhost`

# Special Thanks

This is based on [sepich/nginx-ldap](https://github.com/sepich/nginx-ldap).
I've used some code blocks of his script. Basically I've upgraded his script to python3 and changed the configuration process to use the environment instead of a plain text file.

Since version **0.2.0** most of the code base has changed due to the change of using **ldap3** as ldap module.
