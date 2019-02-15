#!/usr/bin/env python3
import base64
import logging
import os
import pwd
import grp
import sys
import ldap
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn


class AuthHTTPServer(ThreadingMixIn, HTTPServer):
    pass


class LdapAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            auth_header = self.headers.get("Authorization")
            if auth_header and auth_header.lower().startswith("basic "):
                user, passwd = base64.decodebytes(auth_header[6:].encode("utf8")).decode("utf8").split(":", 1)
                if check_auth(user, passwd, self.headers.get("X-Ldap-AllowedUsers"), self.headers.get("X-Ldap-AllowedGroups")):
                    self.send_response(204)
                    return
            self.send_response(401)
            realm = self.headers.get("X-Ldap-Realm")
            if not realm:
                realm = "Authorization required"
            self.send_header("WWW-Authenticate", "Basic realm=\"%s\"" % realm)
            self.send_header("Cache-Control", "no-cache")
        except Exception as err:
            self.send_response(500)
            log.error("Failed to process get request: %s", err)
        finally:
            self.end_headers()


def drop_privileges():
    username = config["ldapauthd"]["user"]
    umask = config["ldapauthd"]["umask"]

    try:
        new_user = pwd.getpwnam(username)
    except KeyError:
        log.error("Could not get passwd entry for %s", username)
        sys.exit(1)

    starting_uid = os.getuid()
    starting_gid = os.getgid()
    starting_username = pwd.getpwuid(starting_uid)[0]
    starting_groupname = grp.getgrgid(starting_gid)[0]

    if starting_uid != 0:
        log.info("Can't drop privileges as we are not root: %s/%s",
                 starting_username, starting_groupname)
        return
        
    try:
        os.setgid(new_user[3])
    except OSError as err:
        log.error("Could not set effective group id: %s", err)

    try:
        os.setuid(new_user[2])
    except OSError as err:
        log.error("Could not set effective user id: %s", err)

    os.umask(umask)
    log.info("Now running as %s/%s", username, grp.getgrgid(new_user[3])[0])


def read_env():
    global config
    config = {
        "ldapauthd": {
            "loglevel": os.getenv("LDAPAUTHD_LOGLEVEL", "INFO"),
            "user": os.getenv("LDAPAUTHD_USER", "nobody"),
            "umask": int(os.getenv("LDAPAUTHD_UMASK", 755)),
            "listen": os.getenv("LDAPAUTHD_IP", "0.0.0.0"),
            "port": int(os.getenv("LDAPAUTHD_PORT", 8080)),
        },
        "ldap": {
            "host": os.getenv("LDAP_HOST"),
            "port": int(os.getenv("LDAP_PORT", 636)),
            "ssl": bool(os.getenv("LDAP_SSL", True)),
            "ssl_validate": bool(os.getenv("LDAP_SSL_VALIDATE", True)),
            "basedn": os.getenv("LDAP_BASEDN"),
            "binddn": os.getenv("LDAP_BINDDN"),
            "bindpw": os.getenv("LDAP_BINDPW"),
        }
    }
    log.setLevel(config["ldapauthd"]["loglevel"])

    for key, item in {"host": "LDAP_HOST",
                      "port": "LDAP_PORT",
                      "basedn": "LDAP_BASEDN",
                      "binddn": "LDAP_BINDDN",
                      "bindpw": "LDAP_BINDPW"}.items():
        if key not in config["ldap"] or not config["ldap"][key]:
            log.error("%s not defined.", item)
            sys.exit(2)

    config["ldap"]["uri"] = "%(proto)s://%(host)s:%(port)d" % {"proto": "ldaps" if config["ldap"]["ssl"] else "ldap",
                                                               "host": config["ldap"]["host"],
                                                               "port": config["ldap"]["port"]}


def check_auth(user, passwd, allowusers, allowgroups):
    try:
        ldap_con = ldap.initialize(config["ldap"]["uri"])
        if not config["ldap"]["ssl_validate"]:
            ldap_con.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        ldap_con.set_option(ldap.OPT_REFERRALS, 0)
        ldap_con.set_option(ldap.OPT_NETWORK_TIMEOUT, 3)
        ldap_con.simple_bind_s(config["ldap"]["binddn"], config["ldap"]["bindpw"])
        data = ldap_con.search_s(base=config["ldap"]["basedn"], scope=ldap.SCOPE_SUBTREE,
                                 filterstr="(&(objectClass=user)(sAMAccountName=%s))" % user)
        if not data:
            return False
        
        data = data[0][1]
        try:
            ldap_con.simple_bind_s(data["distinguishedName"][0].decode("utf8"), passwd)
        except ldap.INVALID_CREDENTIALS:
            return False
        
        if allowusers and user.lower() in [x.lower().strip() for x in allowusers.split(",")]:
            return True
        if allowgroups:
            groups = data["memberOf"]
            if "msSFU30PosixMemberOf" in data:
                groups += data["msSFU30PosixMemberOf"]
            for g in [x.lower().strip() for x in allowgroups.split(",")]:
                for group in groups:
                    if group.decode("utf8").lower().startswith("cn=%s," % g):
                        return True
        return False if allowusers or allowgroups else True
    except (ldap.CONNECT_ERROR, ldap.SERVER_DOWN) as err:
        log.error("Failed to connect to %s: %s", config["ldap"]["uri"], err)
    finally:
        ldap_con.unbind()
    return False


if __name__ == "__main__":
    log = logging.getLogger("ldapauthd")
    logging.basicConfig(format="%(asctime)-15s %(name)s [%(levelname)s]: %(message)s")

    read_env()

    server = AuthHTTPServer((config["ldapauthd"]["listen"], config["ldapauthd"]["port"]), LdapAuthHandler)
    drop_privileges()
    server.serve_forever()
