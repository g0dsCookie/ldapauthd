#!/usr/bin/env python3
import base64
import json
import logging
import os
import pwd
import grp
import sys
import ldap3
import ssl
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
                userinfo = check_auth(user, passwd)
                if userinfo:
                    self.send_response(204)
                    for header_name, header_value in userinfo.items():
                        self.send_header(header_name, header_value)
                    return
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Basic realm=\"%s\"" % config["ldapauthd"]["realm"])
            self.send_header("Cache-Control", "no-cache")
        except Exception as err:
            self.send_response(500)
            log.error("Failed to process get request: %s", err)
        finally:
            self.end_headers()


def in_group(allowed_groups, user_groups):
    for user_group in user_groups:
        if user_group in allowed_groups:
            return True
    return False


def check_auth(username, passwd):
    cfg = config["ldap"]
    allowusers = cfg["allowedUsers"]
    allowgroups = cfg["allowedGroups"]

    if allowusers and username.lower() not in allowusers:
        # we don't need to ask ldap if the user will be rejected anyway
        log.debug("User %s not in allowed users [%s]", username, ", ".join(allowusers))
        return False

    # fetch user info
    with ldap3.Connection(cfg["backends"], user=cfg["binddn"], password=cfg["bindpw"]) as conn:
        if not conn.bound:
            log.error("Could not bind to ldap: %s | %s", conn.result["description"], conn.result["message"])
            return False
        if not conn.search(cfg["basedn"], "(&(objectClass=user)(sAMAccountName=%s))" % username,
                           search_scope=ldap3.SUBTREE, attributes=list(cfg["attributes"].keys()) + ["memberOf"]):
            log.debug("Could not find user %s", username)
            return False
        if not conn.entries or len(conn.entries) < 1:
            log.debug("Could not find user %s", username)
            return False
        user = conn.entries[0]

    if allowgroups and not in_group(allowgroups, user.memberOf):
        # we don't need to authenticate the user if the user is not
        # a member of one of the groups
        log.debug("User %s is not member of any group from [%s]",
                  user.entry_dn, ", ".join(allowgroups))
        return False

    # check users password
    with ldap3.Connection(cfg["backends"], user=user.entry_dn, password=passwd) as conn:
        if not conn.bound:
            log.debug("Could not bind to ldap with user %s: %s | %s",
                      user.entry_dn, conn.result["description"], conn.result["message"])
            return False

    attributes = {}
    for attr_name, header_name in cfg["attributes"].items():
        attributes[header_name] = user[attr_name]
    # Return user informations for latter use
    return attributes


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


def is_true(val):
    return val == "True"


def load_backend_config(name):
    name = "%s_" % name.upper() if name else ""
    cfg = {
        "host": os.getenv("LDAP_%sHOST" % name, None),
        "port": int(os.getenv("LDAP_%sPORT" % name, 636)),
        "ssl": is_true(os.getenv("LDAP_%sSSL" % name, "True")),
        "ssl_validate": is_true(os.getenv("LDAP_%sSSL_VALIDATE", "True")),
    }

    if not cfg["host"]:
        log.error("LDAP_%sHOST not defined.", name)
        sys.exit(2)
    
    if not cfg["ssl_validate"]:
        log.warning("SSL validation for backend %s has been disabled.", cfg["host"])

    return cfg


def get_ldap_srv(backend_cfg):
    if backend_cfg["ssl"]:

        tls = ldap3.Tls(validate=ssl.CERT_REQUIRED if backend_cfg["ssl_validate"] else ssl.CERT_NONE,
                        version=ssl.PROTOCOL_TLSv1)
        return ldap3.Server(host=backend_cfg["host"], port=backend_cfg["port"], use_ssl=True, tls=tls, get_info=False)
    else:
        return ldap3.Server(host=backend_cfg["host"], port=backend_cfg["port"], use_ssl=False, get_info=False)


def populate_groups():
    cfg = config["ldap"]
    if not cfg["allowedGroups"]:
        log.debug("No groups to lookup")
        return

    groups = []
    for group_name in cfg["allowedGroups"]:
        with ldap3.Connection(cfg["backends"], user=cfg["binddn"], password=cfg["bindpw"]) as conn:
            if not conn.search(cfg["basedn"], "(&(objectClass=group)(cn=%s))" % group_name, search_scope=ldap3.SUBTREE) or len(conn.entries) == 0:
                log.error("Could not find group %s", group_name)
                continue
            groups.append(conn.entries[0].entry_dn)
    log.debug("Found groups [%s]", " | ".join(groups))
    cfg["allowedGroups"] = groups


def read_env():
    global config
    config = {
        "ldapauthd": {
            "loglevel": os.getenv("LDAPAUTHD_LOGLEVEL", "INFO"),
            "user": os.getenv("LDAPAUTHD_USER", "nobody"),
            "umask": int(os.getenv("LDAPAUTHD_UMASK", 755)),
            "listen": os.getenv("LDAPAUTHD_IP", "0.0.0.0"),
            "port": int(os.getenv("LDAPAUTHD_PORT", 80)),
            "realm": os.getenv("LDAPAUTHD_REALM", "Authorization required"),
        },
        "ldap": {
            "backends": ldap3.ServerPool(None, ldap3.ROUND_ROBIN, active=True, exhaust=False),
            "allowedUsers": os.getenv("LDAP_ALLOWEDUSERS", "").lower().split(","),
            "allowedGroups": os.getenv("LDAP_ALLOWEDGROUPS", "").split(","),
            "basedn": os.getenv("LDAP_BASEDN"),
            "binddn": os.getenv("LDAP_BINDDN"),
            "bindpw": os.getenv("LDAP_BINDPW"),
            "attributes": {},
        }
    }
    loglevel = logging.getLevelName(config["ldapauthd"]["loglevel"])
    log.setLevel(loglevel)
    ldap3.utils.log.set_library_log_activation_level(logging.ERROR)
    ldap3.utils.log.set_library_log_detail_level(ldap3.utils.log.EXTENDED if loglevel == logging.DEBUG else ldap3.utils.log.ERROR)

    try:
        data = os.getenv("LDAP_ATTRIBUTES", '{"cn": "X-Forwarded-FullName", "mail": "X-Forwarded-Email", "sAMAccountName": "X-Forwarded-User"}')
        config["ldap"]["attributes"] = json.loads(data) if data else {}
    except json.decoder.JSONDecodeError as err:
        log.error("Failed to load LDAP_ATTRIBUTES: %s", err)
        sys.exit(2)

    for key, item in {"basedn": "LDAP_BASEDN",
                      "binddn": "LDAP_BINDDN",
                      "bindpw": "LDAP_BINDPW"}.items():
        if key not in config["ldap"] or not config["ldap"][key]:
            log.error("%s not defined.", item)
            sys.exit(2)

    if len(config["ldap"]["allowedUsers"]) == 1 and not config["ldap"]["allowedUsers"][0]:
        config["ldap"]["allowedUsers"] = None
    if len(config["ldap"]["allowedGroups"]) == 1 and not config["ldap"]["allowedGroups"][0]:
        config["ldap"]["allowedGroups"] = None

    backends = os.getenv("LDAP_BACKENDS", "").split(",")
    if len(backends) > 1:
        config["ldap"]["backends"] = ldap3.ServerPool([get_ldap_srv(load_backend_config(x)) for x in backends],
                                                      ldap3.ROUND_ROBIN, active=True, exhaust=False)
    else:
        config["ldap"]["backends"] = get_ldap_srv(load_backend_config(backends[0]))

    populate_groups()    


if __name__ == "__main__":
    log = logging.getLogger("ldapauthd")
    logging.basicConfig(format="%(asctime)-15s %(name)s [%(levelname)s]: %(message)s")

    read_env()

    server = AuthHTTPServer((config["ldapauthd"]["listen"], config["ldapauthd"]["port"]), LdapAuthHandler)
    drop_privileges()
    server.serve_forever()
