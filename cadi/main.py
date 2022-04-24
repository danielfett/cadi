import argparse
import os

import cherrypy
import jinja2
from pymemcache.client.base import Client as MemcacheClient
from pymemcache.serde import PickleSerde
from yaml import SafeLoader, load

from cadi.server.idp import IDP
from cadi.server.userinterface import UserInterface

from .platform_api import PlatformAPI
from .tools import create_self_signed_certificate

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="CADI Server")
    parser.add_argument("platform_credentials_file", type=argparse.FileType("r"))
    args = parser.parse_args()

    # Prepare Memcache client
    cache = MemcacheClient(("localhost", 11211), serde=PickleSerde())

    # Get self-signed certificate from cache or create new one
    cert_cache_key = "server_certificate"
    (
        server_certificate,
        server_certificate_private_key,
    ) = create_self_signed_certificate()

    # Prepare yes Platform API
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
            server_certificate=server_certificate,
            server_certificate_private_key=server_certificate_private_key,
        ),
        "/idp",
        config={"/": {"error_page.default": STATIC_PATH + "/error.html"}},
    )

    cherrypy.tree.mount(
        WellKnown(),
        "/idp/.well-known",
    )

    cherrypy.engine.start()
    cherrypy.engine.block()
