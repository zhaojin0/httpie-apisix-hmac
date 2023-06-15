"""
ApisixHmacAuth auth plugin for HTTPie.
"""
import base64
import datetime
import hashlib
import hmac
import os

from httpie.plugins import AuthPlugin

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

__version__ = "0.1.0"
__author__ = "Zhao Jin"
__licence__ = "MIT"


class ApisixHmacAuth:
    access_key: str
    secret_key: str
    signed_headers: str
    alg: str = "hmac-sha256"

    def __init__(self, access_key: str, secret_key: str, signed_headers: str, alg: str):
        self.access_key = access_key
        self.secret_key = bytes(secret_key, "utf8")
        self.signed_headers = signed_headers
        self.alg = alg

    def __call__(self, r):
        method = r.method.upper()

        httpdate = r.headers.get("date")

        if not httpdate:
            now = datetime.datetime.utcnow()
            httpdate = now.strftime("%a, %d %b %Y %H:%M:%S GMT")
            r.headers["Date"] = httpdate

        url = urlparse(r.url)

        path = url.path

        query = ""

        if url.query:
            query = url.query
        headers = self.signed_headers.split(";")

        string_to_sign = f"""{method}
{path}
{query}
{self.access_key}
{httpdate}
"""

        headers = self.signed_headers.split(";")

        for key in headers:
            value = r.headers.get(key)
            if not value:
                value = ""
            if isinstance(value, bytes):
                value = str(value, encoding="utf8")
            string_to_sign += f"{key}:{value}\n"

        to_be_sign = bytes(string_to_sign, "utf8")

        if self.alg == "hmac-sha1":
            hash_alg = hashlib.sha1
        else:
            hash_alg = hashlib.sha256

        hash = hmac.new(self.secret_key, to_be_sign, hash_alg)
        signature = base64.b64encode(hash.digest())

        r.headers["X-HMAC-SIGNATURE"] = signature
        r.headers["X-HMAC-ALGORITHM"] = self.alg
        r.headers["X-HMAC-ACCESS-KEY"] = self.access_key
        r.headers["X-HMAC-SIGNED-HEADERS"] = self.signed_headers

        return r


class ApisixHmacAuthPlugin(AuthPlugin):
    name = "Apisix HMAC auth"
    auth_type = "apisix-hmac-auth"
    description = "Sign requests using the Apisix HMCA authentication method"

    def get_auth(self, username:str, password:str ):
        signed_headers = os.environ.get(
            "HMAC_SIGNED_HEADERS", "User-Agent;Content-Type"
        )
        alg = os.environ.get("HMAC_ALGORITHM", "hmac-sha256")
        return ApisixHmacAuth(username, password, signed_headers, alg)
