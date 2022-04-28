import argparse
import os

import cherrypy
import jinja2
from cadi.cache import CADICache
from yaml import SafeLoader, load

from cadi.server.idp import IDP, WellKnown
from cadi.server.userinterface import UserInterface

from .platform_api import PlatformAPI
from .tools import create_new_jwk

if __name__ == "__main__":
    #
    # Environment variables:
    # - CADI_MTLS_HEADER - The name of the header that contains the client TLS certificate
    # - CADI_PLATFORM_CLIENT_ID - The client ID for the platform API
    # - CADI_PLATFORM_CLIENT_CERTIFICATE_B64 - The client TLS certificate for the platform API. PEM format, additionally base64 encoded to fit into an environment variable
    # - CADI_PLATFORM_CLIENT_PRIVATE_KEY_B64 - The client TLS private key for the platform API. PEM format, additionally base64 encoded to fit into an environment variable
    # - CADI_PLATFORM_ENVIRONMENT - The environment for the platform API

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="CADI Server")
    parser.add_argument("platform_credentials_file", type=argparse.FileType("r"))
    args = parser.parse_args()

    # Prepare Memcache client
    cache = CADICache()

    # Get self-signed certificate from cache or create new one
    cert_cache_key = "server_jwk"
    server_jwk = create_new_jwk()

    # Prepare yes Platform API
    # TODO - Take from environment variables
    platform_api = PlatformAPI(
        **load(args.platform_credentials_file.read(), Loader=SafeLoader), cache=cache
    )

    # Prepare Jinja2 Template Engine
    TEMPLATE_PATH = os.path.abspath(os.path.dirname(__file__)) + "/../templates"
    jinja2_env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATE_PATH),
        autoescape=True,
    )

    # Start CherryPy server
    STATIC_PATH = os.path.abspath(os.path.dirname(__file__)) + "/../static"
    cherrypy.tree.mount(
        UserInterface(
            platform_api=platform_api,
            cache=cache,
            j2env=jinja2_env,
        ),
        "/",
        config={
            "/": {
                "tools.staticdir.on": True,
                "tools.staticdir.dir": STATIC_PATH,
                "tools.staticdir.index": "index.html",
                "error_page.default": STATIC_PATH + "/error.html",
            },
        },
    )

    cherrypy.tree.mount(
        IDP(
            platform_api=platform_api,
            cache=cache,
            j2env=jinja2_env,
            server_jwk=server_jwk,
        ),
        "/idp",
        config={"/": {"error_page.default": STATIC_PATH + "/error.html"},
        "/token": {"error_page.default": IDP.json_error_page},
        "/par": {"error_page.default": IDP.json_error_page},
        },
    )

    cherrypy.tree.mount(
        WellKnown(),
        "/idp/.well-known",
    )

    cherrypy.engine.start()
    cherrypy.engine.block()
