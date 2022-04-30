from base64 import urlsafe_b64encode
from hashlib import sha256
import cherrypy
import json
import random
from jwcrypto.jwk import JWK
import string
import os

import markdown2
import bleach
from markupsafe import Markup

from copy import copy


CLIENT_ID_PATTERN = (
    r"sandbox.yes.com:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


def get_base_url():
    if hostname := os.environ.get("WEBSITE_HOSTNAME", None):
        return "https://" + hostname
    return os.environ.get("CADI_BASE_URL", cherrypy.request.base)


def json_handler(*args, **kwargs):
    value = cherrypy.serving.request._json_inner_handler(*args, **kwargs)
    return json.dumps(value, indent=4).encode("utf-8")


def random_string_base64(length: int) -> str:
    return "".join(random.choices(string.digits + string.ascii_letters, k=length))


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


def calculate_pkce_challenge_from_verifier(code_verifier):
    # Given a PKCE code_verifier, calculate the code_challenge according to RFC7636.
    # code_verifier string of random characters.

    return (
        urlsafe_b64encode(sha256(code_verifier.encode("utf-8")).digest())
        .decode("utf-8")
        .replace("=", "")
    )


normal_tags = [
    "a",
    "strong",
    "em",
    "p",
    "ul",
    "ol",
    "li",
    "br",
    "sub",
    "sup",
    "hr",
    "code",
    "tt",
]

inline_tags = ["strong", "em", "code"]


def jinja2_markdown(text):
    html = markdown2.markdown(text, safe_mode=True)
    result = bleach.clean(html, tags=normal_tags, strip=True)
    return Markup(result)


def jinja2_markdown_inline(text):
    html = markdown2.markdown(text, safe_mode=True)
    result = bleach.clean(html, tags=inline_tags, strip=True)
    return Markup(result)
