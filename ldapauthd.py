#!/usr/bin/env python3
import abc
import base64
import json
import ldap3
from ldap3.core.exceptions import LDAPException
import logging
import mmh3
import os
import pwd
import grp
import ssl
import sys
from threading import Lock
import uuid
from http.cookies import SimpleCookie
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from pymemcache.client import base
from pymemcache.exceptions import MemcacheError
from pymemcache import serde


class Ldap:
    ldap3_level_to_detail = {
        "OFF": ldap3.utils.log.OFF,
        "ERROR": ldap3.utils.log.ERROR,
        "BASIC": ldap3.utils.log.BASIC,
        "PROTOCOL": ldap3.utils.log.PROTOCOL,
        "NETWORK": ldap3.utils.log.NETWORK,
        "EXTENDED": ldap3.utils.log.EXTENDED,
    }

    def __init__(self):
        self._basedn = os.getenv("LDAP_BASEDN")
        self._binddn = os.getenv("LDAP_BINDDN")
        self._bindpw = os.getenv("LDAP_BINDPW")

        if not self._basedn:
            log.error("LDAP_BASEDN missing.")
            sys.exit(2)
        if not self._binddn:
            log.error("LDAP_BINDDN missing.")
            sys.exit(2)
        if not self._bindpw:
            log.error("LDAP_BINDPW missing.")
            sys.exit(2)

        self._allowedUsers = to_lower_dict(load_json_env("LDAP_ALLOWEDUSERS"))
        self._allowedGroups = to_lower_dict(load_json_env("LDAP_ALLOWEDGROUPS"))
        self._attributes = load_json_env("LDAP_ATTRIBUTES",
                                         env_default='{"cn": "X-Forwarded-FullName", "mail": "X-Forwarded-Email", "sAMAccountName": "X-Forwarded-User"}',
                                         default={})
        self._roleHeader = os.getenv("LDAP_ROLEHEADER", "X-Forwarded-Role")

        Ldap._set_loglevel(os.getenv("LDAP_LOGLEVEL", "ERROR"))
        self._backend = Ldap._load_backends(os.getenv("LDAP_BACKENDS", "").split(","))

    @staticmethod
    def _load_backend_config(name):
        name = "%s_" % name.upper() if name else ""
        cfg = {
            "host": os.getenv("LDAP_%sHOST" % name, None),
            "port": int(os.getenv("LDAP_%sPORT" % name, 636)),
            "ssl": to_boolean(os.getenv("LDAP_%sSSL" % name, "True")),
            "ssl_validate": to_boolean(os.getenv("LDAP_%sSSL_VALIDATE", "True")),
        }

        if not cfg["host"]:
            log.error("LDAP_%sHOST not defined.", name)
            sys.exit(2)

        if not cfg["ssl_validate"]:
            log.warning("SSL validation for backend %s has been disabled", cfg["host"])

        return cfg

    @staticmethod
    def _get_ldap_srv(cfg):
        if cfg["ssl"]:
            tls = ldap3.Tls(validate=ssl.CERT_REQUIRED if cfg["ssl_validate"] else ssl.CERT_NONE,
                            version=ssl.PROTOCOL_TLSv1)
            return ldap3.Server(host=cfg["host"], port=cfg["port"], use_ssl=True, tls=tls, get_info=False)
        else:
            return ldap3.Server(host=cfg["host"], port=cfg["port"], use_ssl=False, get_info=False)

    @staticmethod
    def _load_backends(backends):
        if len(backends) > 1:
            return ldap3.ServerPool([Ldap._get_ldap_srv(Ldap._load_backend_config(x)) for x in backends],
                                    ldap3.ROUND_ROBIN, active=True, exhaust=False)
        else:
            return Ldap._get_ldap_srv(Ldap._load_backend_config(backends[0]))

    @staticmethod
    def _get_detail_level(name):
        lvl = Ldap.ldap3_level_to_detail.get(name)
        if not lvl:
            raise ValueError("unknown detail level")
        return lvl

    @staticmethod
    def _set_loglevel(loglevel):
        ldap3.utils.log.set_library_log_activation_level(logging.ERROR)
        try:
            ldap3.utils.log.set_library_log_detail_level(Ldap._get_detail_level(loglevel))
        except ValueError:
            log.error("Invalid value for LDAP_LOGLEVEL: %s. Possible values are %s",
                      loglevel,
                      ", ".join(Ldap.ldap3_level_to_detail.keys()))
            sys.exit(2)

    def user_to_role(self, username):
        if not self._allowedUsers:
            return (True, None)
        role = self._allowedUsers.get(username.lower())
        return (role is not None, role)

    def groups_to_role(self, groups):
        if not self._allowedGroups:
            return (True, None)
        for user_group in [x.lower() for x in groups]:
            role = self._allowedGroups.get(user_group)
            if role:
                return (True, role)
        return (False, None)

    def fetch_user_info(self, username):
        with ldap3.Connection(self._backend, user=self._binddn, password=self._bindpw) as conn:
            if not conn.bound:
                log.error("Could not bind to ldap: %s | %s",
                          conn.result["description"],
                          conn.result["message"])
                return None
            if not conn.search(self._basedn, "(&(objectClass=user)(sAMAccountName=%s))" % username,
                               search_scope=ldap3.SUBTREE, attributes=list(self._attributes.keys()) + ["memberOf"]):
                log.error("Could not find user %s", username)
                return None
            if not conn.entries or len(conn.entries) < 1:
                log.error("Could not find user %s", username)
                return None
            return conn.entries[0]

    def check_auth(self, username, password):
        with ldap3.Connection(self._backend, user=username, password=password) as conn:
            if not conn.bound:
                log.debug("Could not bind to ldap with user %s: %s | %s",
                          username, conn.result["description"], conn.result["message"])
                return False
        return True

    def authenticate(self, username, password):
        try:
            userinfo = self.fetch_user_info(username)
        except LDAPException as err:
            log.error("Failed to fetch user informations: %s", err)
            return None
        if not userinfo:
            # user not found
            return None

        try:
            if not self.check_auth(userinfo.entry_dn, password):
                # invalid password
                return None
        except LDAPException as err:
            log.debug("Failed to check users password: %s", err)
            return None

        allowed, role = self.user_to_role(username)
        if not allowed or not role:
            allowed, role = self.groups_to_role(userinfo.memberOf)

        info = {self._roleHeader: role} if role else {}
        for attrname, hdrname in self._attributes.items():
            info[hdrname] = str(userinfo[attrname]).encode("utf8").decode("latin1")
        return info


class SessionHandlerBase(abc.ABC):
    def __init__(self):
        self._ttl = int(os.getenv("LDAPAUTHD_SESSION_TTL", 900))

    @staticmethod
    def get_handler():
        session = os.getenv("LDAPAUTHD_SESSION_STORAGE", "memcached")
        if session == "memcached":
            return MemcacheSession()

        log.critical("Unknown session storage %s", session)
        exit(20)

    @property
    def ttl(self):
        return self._ttl

    def new_session(self):
        session_id = str(uuid.uuid4())
        session = self[session_id] = {}
        return (session_id, session)

    @abc.abstractmethod
    def run(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def close(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def __getitem__(self, key):
        raise NotImplementedError()

    @abc.abstractmethod
    def __setitem__(self, key, value):
        raise NotImplementedError()


class MemcacheSession(SessionHandlerBase):
    def __init__(self):
        super().__init__()
        host = os.getenv("LDAPAUTHD_SESSION_HOST", "localhost:11211")
        if not host.startswith("/"):
            (host, port) = host.split(":", maxsplit=1)
            host = (host, int(port))
        self._lock = Lock()
        _opts = {
            "serializer": serde.python_memcache_serializer,
            "deserializer": serde.python_memcache_deserializer,
            "connect_timeout": 10,
            "timeout": 5,
            "no_delay": True,
            "key_prefix": b"lad_sess_",
        }
        self._client = base.Client(host, **_opts)

    @staticmethod
    def _normalize_key(key):
        return base64.encodebytes(mmh3.hash_bytes(key)).strip()

    def run(self):
        pass

    def close(self):
        self._client.quit()

    def __getitem__(self, key):
        try:
            self._lock.acquire()
            return self._client.get(self._normalize_key(key))
        except MemcacheError as err:
            log.error("Failed to get session from memcache: %s", err)
            return None
        finally:
            self._lock.release()

    def __setitem__(self, key, value):
        try:
            self._lock.acquire()
            self._client.set(self._normalize_key(key), value, expire=self.ttl)
        except MemcacheError as err:
            log.error("Failed to store session in memcache: %s", err)
        finally:
            self._lock.release()


class AuthHTTPServer(ThreadingMixIn, HTTPServer):
    pass


class LdapAuthHandler(BaseHTTPRequestHandler):
    @property
    def authorization(self):
        hdr = self.headers.get("Authorization")
        if not hdr or not hdr.lower().startswith("basic "):
            return None
        return base64.decodebytes(hdr[6:].encode("utf8")) \
            .decode("utf8").split(":", 1)

    @property
    def realuri(self):
        host = self.headers.get("X-Forwarded-Host")
        path = self.headers.get("X-Forwarded-Uri")
        return "%s://%s%s" % ("http", host, path)

    def log_message(self, format, *args):
        log.info("%s - - %s" % (self.client_address[0], format % args))

    def init_session(self):
        cookie = SimpleCookie(self.headers.get("Cookie"))
        sid = cookie.get("_ldapauthd_sess", None)

        if sid:
            self.session_id = sid.value
            self.session = sessions[self.session_id]
            if self.session:
                # session_id is valid
                log.debug("Got valid session with id %s", self.session_id)
                return True
            log.debug("Got invalid session with id %s", self.session_id)

        (self.session_id, self.session) = sessions.new_session()
        log.debug("Initialized new session with id %s", self.session_id)
        return False

    def unauth_header(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="%s"' % realm)
        self.send_header("Cache-Control", "no-cache")

    def fail_header(self, exc=None):
        if exc:
            log.error(exc)
        self.send_response(500)

    def do_GET(self):
        try:
            if self.init_session() and len(self.session) > 0:
                self.send_response(204)
                log.debug("Sending headers: %s", self.session)
                for hdr, val in self.session.items():
                    self.send_header(hdr, val)
                return

            auth_header = self.authorization
            if not auth_header:
                if self.headers.get("Authorization"):
                    log.error("Failed to parse authorization header")
                    log.debug("Authorization header: %s", auth_header)
                    self.fail_header()
                    return
                self.unauth_header()
                return

            usr = ldap.authenticate(*auth_header)
            if not usr:
                log.error("Failed to authenticate user")
                self.unauth_header()
                return

            cookie = SimpleCookie()
            cookie["_ldapauthd_sess"] = self.session_id
            if cookie_domain:
                cookie["_ldapauthd_sess"]["domain"] = cookie_domain

            self.send_response(307)
            self.send_header("Set-Cookie", cookie["_ldapauthd_sess"].OutputString())
            self.send_header("Location", self.realuri)
            for hdr, val in usr.items():
                self.send_header(hdr, val)
                self.session[hdr] = val
            sessions[self.session_id] = self.session
        except Exception as err:
            self.fail_header(err)
        finally:
            self.end_headers()


def drop_privileges(username):
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

    log.info("Now running as %s/%s", username, grp.getgrgid(new_user[3])[0])


def to_boolean(val):
    val = val.lower()
    if val == "true" or val == "1":
        return True
    elif val == "false" or val == "0":
        return False
    raise ValueError("Unknown boolean value")


def load_json_env(name, env_default=None, default=None):
    try:
        data = os.getenv(name, env_default)
        return json.loads(data) if data else default
    except json.decoder.JSONDecodeError as err:
        log.error("Failed to load %s: %s", name, err)
        sys.exit(2)


def to_lower_dict(data):
    return {k.lower(): v for k, v in data.items()} if data else data


if __name__ == "__main__":
    log = logging.getLogger("ldapauthd")
    log.setLevel(os.getenv("LDAPAUTHD_LOGLEVEL", "INFO"))
    logging.basicConfig(format="%(asctime)-15s %(name)s [%(levelname)s]: %(message)s")

    realm = os.getenv("LDAPAUTHD_REALM", "Authorization required")
    cookie_domain = os.getenv("LDAPAUTHD_SESSION_DOMAIN", None)

    sessions = SessionHandlerBase.get_handler()
    sessions.run()

    ldap = Ldap()

    listen = os.getenv("LDAPAUTHD_IP", "0.0.0.0")
    port = int(os.getenv("LDAPAUTHD_PORT", 80))
    server = AuthHTTPServer((listen, port), LdapAuthHandler)

    drop_privileges(os.getenv("LDAPAUTHD_USER", "nobody"))

    server.serve_forever()
