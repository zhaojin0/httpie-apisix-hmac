
from httpie_apisix_hmac import ApisixHmacAuth
from collections import namedtuple


USER_KEY = "user-key"
SECRET_KEY = "my-secret-key"

SIGNED_HEADERS="User-Agent;x-custom-a"


Request = namedtuple("Request", ["method", "url", "headers"])



def test_signature():
    auth = ApisixHmacAuth(USER_KEY, SECRET_KEY, SIGNED_HEADERS, "hmac-sha256")
    request = Request(
        method="GET",
        url="/index.html?age=36&name=james",
        headers={
            "date": "Tue, 19 Jan 2021 11:33:20 GMT",
            "User-Agent": "curl/7.29.0",
            "x-custom-a": "test"
        }
    )

    signed_req = auth(request)

    sig = signed_req.headers["X-HMAC-SIGNATURE"] 
    alg = signed_req.headers["X-HMAC-ALGORITHM"] 
    key = signed_req.headers["X-HMAC-ACCESS-KEY"] 

    assert sig == b"8XV1GB7Tq23OJcoz6wjqTs4ZLxr9DiLoY4PxzScWGYg="
    assert alg == "hmac-sha256"
    assert key == USER_KEY

