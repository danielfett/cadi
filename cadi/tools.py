import cherrypy
import json
import random
from cryptography.hazmat.primitives.serialization import Encoding
from jwcrypto.jwk import JWK
import string


CLIENT_ID_PATTERN = (
    r"sandbox.yes.com:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


def json_handler(*args, **kwargs):
    value = cherrypy.serving.request._json_inner_handler(*args, **kwargs)
    return json.dumps(value, indent=4).encode("utf-8")


def random_string_base64(length: int) -> str:
    return ''.join(random.choices(string.digits + string.ascii_letters, k=length))


def create_new_jwk():
    jwk = JWK.generate(kty="RSA", size=2048)
    return jwk

def jwk_to_jwks(jwk):
    jwk_dict = jwk.export_public(as_dict=True)
    jwk_dict["use"] = ["sig"]
    jwk_dict["kid"] = "default"
    # Create a JWKS from the public key, including the x5c property
    jwks = {"keys": [jwk_dict]}
    return jwks

