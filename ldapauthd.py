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
    def log_message(self, format, *args):
        log.info("%s - - %s" % (self.client_address[0], format % args))

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
    attributes = {}
    allowed = not bool(allowusers or allowgroups)

    if not allowed and allowusers:
        username_lower = username.lower()
        log.debug("Checking if user %s is explicitly allowed...", username)
        if username_lower in allowusers:
            attributes[cfg["roleHeader"]] = allowusers[username_lower]
            log.debug("User %s is explicitly allowed, Role %s will be assigned", username, allowusers[username_lower])
            allowed = True

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

    if not allowed and allowgroups:
        log.debug("Checking if user %s is allowed by group...", username)
        for user_group in [x.lower() for x in user.memberOf]:
            if user_group in allowgroups:
                attributes[cfg["roleHeader"]] = allowgroups[user_group]
                log.debug("User %s is allowed, Role %s will be assigned", username, allowgroups[user_group])
                allowed = True
                break

    if not allowed:
        log.debug("User %s is not member of any allowed group and not explicitly allowed.", user.entry_dn)
        return False

    # check users password
    with ldap3.Connection(cfg["backends"], user=user.entry_dn, password=passwd) as conn:
        if not conn.bound:
            log.debug("Could not bind to ldap with user %s: %s | %s",
                      user.entry_dn, conn.result["description"], conn.result["message"])
            return False
    
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


ldap3_level_to_detail = {
    "OFF": ldap3.utils.log.OFF,
    "ERROR": ldap3.utils.log.ERROR,
    "BASIC": ldap3.utils.log.BASIC,
    "PROTOCOL": ldap3.utils.log.PROTOCOL,
    "NETWORK": ldap3.utils.log.NETWORK,
    "EXTENDED": ldap3.utils.log.EXTENDED,
}


def ldap3_level_name_to_detail(level_name):
    if level_name in ldap3_level_to_detail:
        return ldap3_level_to_detail[level_name]
    raise ValueError("unknown detail level")


def load_json_env(name, env_default=None, default=None):
    try:
        data = os.getenv(name, env_default)
        return json.loads(data) if data else default
    except json.decoder.JSONDecodeError as err:
        log.error("Failed to load %s: %s", name, err)
        sys.exit(2)


def to_lower_dict(data):
    return {k.lower():v for k, v in data.items()} if data else data


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
            "loglevel": os.getenv("LDAP_LOGLEVEL", "ERROR"),
            "backends": ldap3.ServerPool(None, ldap3.ROUND_ROBIN, active=True, exhaust=False),
            "allowedUsers": to_lower_dict(load_json_env("LDAP_ALLOWEDUSERS")),
            "allowedGroups": to_lower_dict(load_json_env("LDAP_ALLOWEDGROUPS")),
            "basedn": os.getenv("LDAP_BASEDN"),
            "binddn": os.getenv("LDAP_BINDDN"),
            "bindpw": os.getenv("LDAP_BINDPW"),
            "attributes": load_json_env("LDAP_ATTRIBUTES",
                                        env_default='{"cn": "X-Forwarded-FullName", "mail": "X-Forwarded-Email", "sAMAccountName": "X-Forwarded-User"}',
                                        default={}),
            "roleHeader": os.getenv("LDAP_ROLEHEADER", "X-Forwarded-Role"),
        }
    }
    log.setLevel(config["ldapauthd"]["loglevel"])
    ldap3.utils.log.set_library_log_activation_level(logging.ERROR)
    try:
        ldap3.utils.log.set_library_log_detail_level(ldap3_level_name_to_detail(config["ldap"]["loglevel"]))
    except ValueError:
        log.error("Invalid loglevel for LDAP_LOGLEVEL: %s. Possible values are %s", config["ldap"]["loglevel"], ", ".join(ldap3_level_to_detail.keys()))
        sys.exit(2)

    for key, item in {"basedn": "LDAP_BASEDN",
                      "binddn": "LDAP_BINDDN",
                      "bindpw": "LDAP_BINDPW"}.items():
        if key not in config["ldap"] or not config["ldap"][key]:
            log.error("%s not defined.", item)
            sys.exit(2)

    backends = os.getenv("LDAP_BACKENDS", "").split(",")
    if len(backends) > 1:
        config["ldap"]["backends"] = ldap3.ServerPool([get_ldap_srv(load_backend_config(x)) for x in backends],
                                                      ldap3.ROUND_ROBIN, active=True, exhaust=False)
    else:
        config["ldap"]["backends"] = get_ldap_srv(load_backend_config(backends[0]))

    if config["ldap"]["allowedUsers"]:
        log.debug("Users explicitly allowed to authenticate: %s", ", ".join(config["ldap"]["allowedUsers"].keys()))
    if config["ldap"]["allowedGroups"]:
        log.debug("Groups allowed to authenticate: %s", ", ".join(config["ldap"]["allowedGroups"].keys()))


if __name__ == "__main__":
    log = logging.getLogger("ldapauthd")
    logging.basicConfig(format="%(asctime)-15s %(name)s [%(levelname)s]: %(message)s")

    read_env()

    server = AuthHTTPServer((config["ldapauthd"]["listen"], config["ldapauthd"]["port"]), LdapAuthHandler)
    drop_privileges()
    server.serve_forever()
