#!/usr/bin/env python3
import abc
import base64
import json
import ldap3
import logging
import os
import pwd
import grp
import random
import string
import ssl
import sys
import threading
import time
import uuid
from http.cookies import SimpleCookie
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn


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

        log.debug(self._attributes)
        log.debug(self._roleHeader)

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
        userinfo = self.fetch_user_info(username)
        if not userinfo:
            # user not found
            return None

        if not self.check_auth(userinfo.entry_dn, password):
            # invalid password
            return None

        allowed, role = self.user_to_role(username)
        if not allowed or not role:
            allowed, role = self.groups_to_role(userinfo.memberOf)

        info = {self._roleHeader: role} if role else {}
        for attrname, hdrname in self._attributes.items():
            info[hdrname] = str(userinfo[attrname]).encode("utf8").decode("latin1")
        return info


class UserSession:
    def __init__(self, sessionId):
        self._sessionId = sessionId
        self._headers = {}
    
    @property
    def sessionId(self):
        return self._sessionId

    def __contains__(self, key):
        return key in self._headers

    def __getitem__(self, key):
        return self._headers[key]
    
    def __setitem__(self, key, value):
        self._headers[key] = value
    
    def __delitem__(self, key):
        del self._headers[key]

    def __len__(self):
        return self._headers.__len__()

    def __iter__(self):
        return self._headers.__iter__()


class SessionHandlerBase(abc.ABC):
    def __init__(self, ttl, id_length = 16, session_chars = string.ascii_letters + string.digits):
        self._ttl = ttl
        self._id_length = id_length

    @staticmethod
    def get_handler():
        session = os.getenv("LDAPAUTHD_SESSION_STORAGE", "memory")
        ttl = int(os.getenv("LDAPAUTHD_SESSION_TTL", 900))

        if session == "memory":
            return InMemorySession(ttl)

        log.critical("Unknown session storage %s", session)
        exit(20)

    @property
    def ttl(self):
        return self._ttl

    @property
    def id_length(self):
        return self._id_length

    def get_session(self, session_id):
        if session_id and session_id in self:
            return self[session_id]
        session = UserSession(uuid.uuid4())
        self[session.sessionId] = session
        return session

    @abc.abstractmethod
    def run(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def close(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def __contains__(self, key):
        raise NotImplementedError()

    @abc.abstractmethod
    def __getitem__(self, key):
        raise NotImplementedError()

    @abc.abstractmethod
    def __setitem__(self, key, value):
        raise NotImplementedError()


class InMemorySession(SessionHandlerBase):
    def __init__(self, ttl):
        super().__init__(ttl)
        self._sessions = {}
        self._sessions_lock = threading.Lock()
        self._cleanup_thread = None

    @staticmethod
    def _is_valid(item):
        return item["ttl"] > time.time()

    def _cleanup(self):
        log.debug("Cleanup thread for in-memory sessions started")
        t = threading.current_thread()
        i = 0
        while not getattr(t, "stop_requested", False):
            if i >= 10:
                # only run cleanup check every 10 seconds
                with self._sessions_lock:
                    for todel in [k for k, v in self._sessions if not InMemorySession._is_valid(v)]:
                        del self._sessions[todel]
                        log.debug("Session with id %s expired", todel)
                i = 0
            else:
                i += 1
            time.sleep(1)
        log.debug("Cleanup thread for in-memory sessions stopped")

    def run(self):
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            return
        self._cleanup_thread = threading.Thread(target=self._cleanup, name="Session Cleanup")
        self._cleanup_thread.start()

    def close(self):
        if not self._cleanup_thread or not self._cleanup_thread.is_alive():
            self._cleanup_thread = None
            return
        self._cleanup_thread.stop_requested = True
        self._cleanup_thread.join()
        self._cleanup_thread = None
        self._sessions = {}

    def __contains__(self, key):
        with self._sessions_lock:
            return key in self._sessions and InMemorySession._is_valid(self._sessions[key])

    def __getitem__(self, key):
        with self._sessions_lock:
            s = self._sessions[key]
            if not InMemorySession._is_valid(s):
                # generate new session and drop old one
                s = {
                    "ttl": time.time() + self.ttl,
                    "value": UserSession(key),
                }
                self._sessions[key] = s
            return s["value"]

    def __setitem__(self, key, value):
        with self._sessions_lock:
            self._sessions[key] = {
                "ttl": time.time() + self.ttl,
                "value": value,
            }


class AuthHTTPServer(ThreadingMixIn, HTTPServer):
    pass


class LdapAuthHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        log.info("%s - - %s" % (self.client_address[0], format % args))

    def authenticate(self, user, passwd):
        return ldap.authenticate(user, passwd)

    def do_GET(self):
        try:
            auth_header = self.headers.get("Authorization")
            log.debug(self.headers.get("Cookie", "No Cookie"))
            if auth_header and auth_header.lower().startswith("basic "):
                userinfo = self.authenticate(*base64.decodebytes(auth_header[6:].encode("utf8")).decode("utf8").split(":", 1))
                if userinfo:
                    self.send_response(204)
                    for header_name, header_value in userinfo.items():
                        self.send_header(header_name, header_value)
                    return
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Basic realm=\"%s\"" % realm)
            self.send_header("Cache-Control", "no-cache")
        except Exception as err:
            self.send_response(500)
            log.error("Failed to process get request: %s", err)
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
    return {k.lower():v for k, v in data.items()} if data else data


if __name__ == "__main__":
    log = logging.getLogger("ldapauthd")
    log.setLevel(os.getenv("LDAPAUTHD_LOGLEVEL", "INFO"))
    logging.basicConfig(format="%(asctime)-15s %(name)s [%(levelname)s]: %(message)s")

    realm = os.getenv("LDAPAUTHD_REALM", "Authorization required")

    sessions = SessionHandlerBase.get_handler()
    ldap = Ldap()

    listen = os.getenv("LDAPAUTHD_IP", "0.0.0.0")
    port = int(os.getenv("LDAPAUTHD_PORT", 80))
    server = AuthHTTPServer((listen, port), LdapAuthHandler)

    drop_privileges(os.getenv("LDAPAUTHD_USER", "nobody"))

    server.serve_forever()
