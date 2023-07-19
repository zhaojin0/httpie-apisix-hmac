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
    from urlparse import urlparse, parse_qs, quote
except ImportError:
    from urllib.parse import urlparse, parse_qs, quote

import itertools

__version__ = "0.1.0"
__author__ = "Zhao Jin"
__licence__ = "MIT"


def _uri_encode(key: str, values: list[str]) -> list[str]:
    """
    encode multiple values
    Args:
        key: key of query param
        values: values of query param
    Returns:
        query string
    """
    if not values or (len(values) == 1 and values[0] == ""):
        return [f"{key}="]

    return [f"{key}={quote(v)}" for v in values]
    # list(map(lambda v: key + "=" + v, map(lambda x: quote(x), values)))


def _build_canonical_query_string(query: str) -> str:
    """
    build hmac canonical query string

    Parameter:
        query: query string

    Returns:
        canonical query_string to be sign
    """
    query_dict = parse_qs(query, keep_blank_values=True)

    sorted_keys = sorted(query_dict.keys())

    qs = [_uri_encode(k, query_dict[k]) for k in sorted_keys]

    items = itertools.chain.from_iterable(qs)

    _canonical_query_string = "&".join(items)

    return _canonical_query_string


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
            query = _build_canonical_query_string(url.query)

        string_to_sign = f"""{method}
{path}
{query}
{self.access_key}
{httpdate}
"""

        headers = self.signed_headers.split(";")

        for key in headers:
            lk = key.lower()
            value = r.headers.get(lk)
            if not value:
                value = ""
                if lk == "host":
                  value = url.hostname

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

    def get_auth(self, username: str, password: str):
        signed_headers = os.environ.get(
            "HMAC_SIGNED_HEADERS", "User-Agent;Content-Type"
        )
        alg = os.environ.get("HMAC_ALGORITHM", "hmac-sha256")
        return ApisixHmacAuth(username, password, signed_headers, alg)
