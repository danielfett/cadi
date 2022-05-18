import argparse
import os
import logging

import cherrypy
import jinja2
from cadi.cache import CADICache
from yaml import SafeLoader, load

from cadi.server.idp import IDP, WellKnown
from cadi.server.userinterface import UserInterface

from .platform_api import DummyAPI, PlatformAPI
from .tools import create_new_jwk, jinja2_markdown, jinja2_markdown_inline

if __name__ == "__main__":
    # Set up logger
    logging.basicConfig(level=logging.DEBUG)

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="CADI Server")
    parser.add_argument("platform_credentials_file", type=argparse.FileType("r"))
    # When "--dummy-api" is provided, use DummyAPI instead of PlatformAPI
    parser.add_argument("--dummy-api", action="store_true")
    args = parser.parse_args()

    # Prepare Memcache client
    cache = CADICache()

    # Get self-signed certificate from cache or create new one
    cert_cache_key = "server_jwk"
    server_jwk = create_new_jwk()

    # Prepare yes Platform API
    if not args.dummy_api:
        platform_api = PlatformAPI(
            **load(args.platform_credentials_file.read(), Loader=SafeLoader),
            cache=cache
        )
    else:
        platform_api = DummyAPI()

    # Prepare Jinja2 Template Engine
    TEMPLATE_PATH = os.path.abspath(os.path.dirname(__file__)) + "/../templates"
    jinja2_env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATE_PATH),
        autoescape=True,
    )
    jinja2_env.filters["md"] = jinja2_markdown
    jinja2_env.filters["md_inline"] = jinja2_markdown_inline

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
        config={
            "/": {"error_page.default": STATIC_PATH + "/error.html"},
            "/token": {"error_page.default": IDP.json_error_page},
            "/par": {"error_page.default": IDP.json_error_page},
        },
    )

    cherrypy.tree.mount(
        WellKnown(),
        "/idp/.well-known",
    )

    cherrypy.__version__ = ""
    cherrypy.config.update(
        {
            "response.headers.server": "",
        }
    )

    cherrypy.server.socket_host = "0.0.0.0"
    cherrypy.server.socket_port = 8000

    cherrypy.engine.start()
    cherrypy.engine.block()
