import argparse
import json
import os
import re
from typing import Dict, List

import cherrypy
import jinja2
from prometheus_client import Enum
from pymemcache.client.base import Client as MemcacheClient
from pymemcache.serde import PickleSerde
from yaml import SafeLoader, load
from furl import furl
from cadi.idp.ekyc import YES_CLAIMS, YES_VERIFIED_CLAIMS, ClaimsProvider
from cadi.idp.session import SessionManager

from cadi.rptests.token import TokenRequestTestSet
from cadi.rptests.userinfo import UserinfoRequestTestSet

from .platform_api import PlatformAPI
from .rptestmechanics import RPTestResultStatus
from .rptests.par import (
    PARRequestURIAuthorizationRequestTestSet,
    PushedAuthorizationRequestTestSet,
)
from .rptests.traditional import TraditionalAuthorizationRequestTestSet
from .tools import (
    CLIENT_ID_PATTERN,
    create_self_signed_certificate,
    convert_to_jwks,
    insert_into_cache_list,
)


TEST_RESULT_STATUS_MAPPING = {
    RPTestResultStatus.SUCCESS: {
        "text": "Success",
        "color": "success",
        "description": "The feature is used correctly",
        "icon": "check-circle",
    },
    RPTestResultStatus.WARNING: {
        "text": "Warning",
        "color": "warning",
        "description": "The current usage of the feature may lead to problems in practice",
        "icon": "exclamation-circle",
    },
    RPTestResultStatus.FAILURE: {
        "text": "Failure",
        "color": "danger",
        "description": "This will lead to an error in practice",
        "icon": "exclamation-circle",
    },
    RPTestResultStatus.SKIPPED: {
        "text": "Test was skipped",
        "color": "muted",
        "description": "There was no need to run this test or the prerequisites are not met",
        "icon": "slash-circle",
    },
    RPTestResultStatus.INFO: {
        "text": "Info",
        "color": "info",
        "description": "Informative - not indicating a problem",
        "icon": "info-circle",
    },
    RPTestResultStatus.WAITING: {
        "text": "Waiting",
        "color": "primary",
        "description": "The test is waiting for a prerequisite to be met",
        "icon": "question-circle",
    },
}


class CADIDP:
    MAX_TEST_RESULTS = 10
    TEST_RESULT_EXPIRATION = 60 * 60 * 12  # 12 hours
    MAX_RETRIES_CHECK_AND_SET = 12

    def __init__(
        self,
        platform_api: PlatformAPI,
        cache: MemcacheClient,
        j2env,
        server_certificate,
        server_certificate_private_key,
    ):
        self.platform_api = platform_api
        self.cache = cache
        self.j2env = j2env
        self.server_certificate = server_certificate
        self.server_certificate_private_key = server_certificate_private_key
        self.session_manager = SessionManager(cache)
        self.claims_provider = ClaimsProvider()

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def par(self, *args, **kwargs):
        client_id = self._test_for_client_id(kwargs)
        test = PushedAuthorizationRequestTestSet(
            self.platform_api,
            cache=self.cache,
            request=cherrypy.request,
            expected_client_id=client_id,
        )

        test_results = test.run()
        self._attach_test_results(client_id, test_results)

        if not "session" in test.data:
            return {
                "error": "server_error",
                "error_description": "We were not able to complete your request. "
                f"Please check the logs available at {cherrypy.request.base}/logs?client_id={client_id} for any errors.",
            }

        else:
            return {
                "request_uri": test.data["session"].request_uri,
                "expires_in": PARRequestURIAuthorizationRequestTestSet.REQUEST_URI_EXPIRE_WARNING_AFTER,
            }

    @cherrypy.expose
    def auth(self, *args, **kwargs):
        client_id = self._test_for_client_id(kwargs)

        if "request_uri" in kwargs:
            test_to_run = PARRequestURIAuthorizationRequestTestSet
        else:
            test_to_run = TraditionalAuthorizationRequestTestSet

        test = test_to_run(
            self.platform_api,
            cache=self.cache,
            request=cherrypy.request,
            expected_client_id=client_id,
        )

        test_results = test.run()
        self._attach_test_results(client_id, test_results)

        if "session" in test.data:
            session_id = test.data["session"].sid
            users_list = self.claims_provider.get_all_users()
        else:
            session_id = None
            users_list = []

        # Render the auth_ep.html template
        template = self.j2env.get_template("auth_ep.html")
        return template.render(
            client_id=client_id,
            test_results=test_results,
            stats=test_results.get_stats(),
            session_id=session_id,
            Status=RPTestResultStatus,
            SM=TEST_RESULT_STATUS_MAPPING,
            users_list=users_list,
        )

    @cherrypy.expose
    def auth_response_modifications(self, client_id, sid, user_id):
        session = self.session_manager.find(client_id=client_id, sid=sid)
        if session is None:
            raise cherrypy.HTTPError(
                400,
                "No session with this sid exists for this client ID. Please start a new authorization session.",
            )

        response_id_token_normal = self.claims_provider.process_ekyc_request(
            user_id, session, "id_token", False
        )
        response_id_token_minimal = self.claims_provider.process_ekyc_request(
            user_id, session, "id_token", True
        )
        response_userinfo_normal = self.claims_provider.process_ekyc_request(
            user_id, session, "userinfo", False
        )
        response_userinfo_minimal = self.claims_provider.process_ekyc_request(
            user_id, session, "userinfo", True
        )

        # Render the auth_ep.html template
        template = self.j2env.get_template("auth_ep_resp_mod.html")
        return template.render(
            client_id=client_id,
            session_id=session.sid,
            response_id_token_normal=response_id_token_normal,
            response_id_token_minimal=response_id_token_minimal,
            response_userinfo_normal=response_userinfo_normal,
            response_userinfo_minimal=response_userinfo_minimal,
        )

    @cherrypy.expose
    def auth_continue(
        self,
        client_id,
        sid,
        id_token_content_selector,
        id_token_content_left,
        id_token_content_right,
        userinfo_content_selector,
        userinfo_content_left,
        userinfo_content_right,
    ):
        session = self.session_manager.find(client_id=client_id, sid=sid)
        if session is None:
            raise cherrypy.HTTPError(
                400,
                "No session with this sid exists for this client ID. Please start a new authorization session.",
            )

        if id_token_content_selector == "left":
            session.id_token_response_contents = json.loads(id_token_content_left)
        else:
            session.id_token_response_contents = json.loads(id_token_content_right)

        if userinfo_content_selector == "left":
            session.userinfo_response_contents = json.loads(userinfo_content_left)
        else:
            session.userinfo_response_contents = json.loads(userinfo_content_right)

        # Use furl library to assemble the redirect URI with the redirect URI from the session.
        # Parameters: state, code, and iss
        redirect_uri = furl(session.redirect_uri)
        if session.state is not None:
            redirect_uri.args["state"] = session.state
        redirect_uri.args["code"] = session.code
        redirect_uri.args["iss"] = cherrypy.request.base + "/idp"

        # Redirect browser to redirect_uri
        raise cherrypy.HTTPRedirect(redirect_uri.url)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def token(self, *args, **kwargs):
        client_id = self._desperately_find_client_id(kwargs, cherrypy.request)
        if not client_id:
            raise cherrypy.HTTPError(
                400,
                "Missing client_id! We looked for it in the URL and the request body, but we couldn't find it.",
            )

        test = TokenRequestTestSet(
            self.platform_api,
            cache=self.cache,
            request=cherrypy.request,
            expected_client_id=client_id,
        )

        if not "session" in test.data:
            return {
                "error": "server_error",
                "error_description": "We were unable to identify the session to which your request belongs. "
                "Please ensure that your token request is conformant to the token request format defined in RFC6749! "
                f"Please check the logs available at {cherrypy.request.base}/logs?client_id={client_id} for any errors.",
            }

        session = test.data["session"]

        id_token = self._create_id_token(session)

        return {
            "access_token": session.access_token,
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": SessionManager.SESSION_EXPIRATION,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        }

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def userinfo(self):
        authorization_header = cherrypy.request.headers.get("authorization", None)

        if authorization_header is None:
            return {
                "error": "invalid_request",
                "error_description": "The request does not contain an 'Authorization' header. "
                "You must provide the 'Authorization' header with an access token. "
                "Please review the OpenID Connect core specification for the userinfo endpoint.",
            }

        if not authorization_header.startswith("Bearer "):
            return {
                "error": "invalid_request",
                "error_description": "The Authorization header provided does not start with 'Bearer '. "
                "Please review the OpenID Connect core specification for the userinfo endpoint.",
            }

        session = self.session_manager.find_by_access_token(authorization_header[7:])

        if session is None:
            return {
                "error": "invalid_request",
                "error_description": "The access token provided in the Authorization header is unknown or has expired. "
                "Please review the OpenID Connect core specification for the userinfo endpoint.",
            }

        client_id = session.client_id

        test = UserinfoRequestTestSet(
            platform_api=self.platform_api,
            cache=self.cache,
            client_id=client_id,
            session=session,
        )

        test.run()

        return session.userinfo_response_contents

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def jwks(self):
        # JWKS Endpoint: Serve the server certificate
        return convert_to_jwks(self.server_certificate)

    def _attach_test_results(self, client_id, test_results):
        key = "test_results_" + client_id
        insert_into_cache_list(
            cache, key, test_results, self.MAX_TEST_RESULTS, self.TEST_RESULT_EXPIRATION
        )

    def _desperately_find_client_id(self, parameters, request):
        # Check if the client ID is in the URL or the form-encoded body
        if "client_id" in parameters and re.match(
            CLIENT_ID_PATTERN, parameters["client_id"]
        ):
            return parameters["client_id"]

        # try to decode the body if it is json and extract the client_id
        try:
            body = request.body.read().decode("utf-8")
            try:
                payload = json.loads(body)
                if re.match(CLIENT_ID_PATTERN, payload["client_id"]):
                    return payload["client_id"]
            except Exception:
                pass

            # try to extract (using a regex) the client_id from the body and the query
            client_id = re.search(CLIENT_ID_PATTERN, body)
            if client_id:
                return client_id.group(0)
        except Exception:
            pass

        client_id = re.search(CLIENT_ID_PATTERN, request.request_line)
        if client_id:
            return client_id.group(0)

        return None

    def _test_for_client_id(self, kwargs):
        client_id = self._desperately_find_client_id(kwargs, cherrypy.request)
        if not client_id:
            raise cherrypy.HTTPError(
                400,
                "Missing client_id! We looked for it in the URL and the request body, but we couldn't find it.",
            )
        return client_id

    def _create_id_token(self, session):
        return session.id_token_response_contents


class Root:
    def __init__(self, platform_api: PlatformAPI, cache: MemcacheClient, j2env):
        self.platform_api = platform_api
        self.cache = cache
        self.j2env = j2env

    @cherrypy.expose
    def index(self, client_id=None, error=None):
        # Check if the client ID matches the right format
        if client_id and not re.match(CLIENT_ID_PATTERN, client_id):
            client_id = None

        # Render the index.html.j2 template
        template = self.j2env.get_template("index.html")
        return template.render(
            client_id=client_id,
            error=error,
        )

    @cherrypy.expose
    def log(self, client_id):
        client_config = self._get_client_config(client_id)

        test_results = self.cache.get(f"test_results_{client_id}", default=[])

        # Mapping from RPTestResultStatus to text, bootstrap text color, description and icon

        # Render the index.html.j2 template
        template = self.j2env.get_template("log.html")
        return template.render(
            client_id=client_id,
            client_config=client_config,
            test_results=test_results,
            id=id,
            Status=RPTestResultStatus,
            SM=TEST_RESULT_STATUS_MAPPING,
        )

    def _get_client_config(self, client_id):
        # Client-IDs are all lowercase
        client_id = client_id.lower()

        # Check if the client_id has the correct format of sandbox.yes.com:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        if not re.match(
            CLIENT_ID_PATTERN,
            client_id,
        ):
            # Redirect to the index page with a parameter saying that the client_id is invalid
            raise cherrypy.HTTPRedirect(
                f"/?client_id={client_id}&error=invalid_client_id_format"
            )

        client_config = self.platform_api.get_client_config_with_cache(client_id)
        if client_config is None:
            # Redirect to the index page with a parameter saying that the client_id is invalid
            raise cherrypy.HTTPRedirect(
                f"/?client_id={client_id}&error=invalid_client_id"
            )
        return client_config


"""
Serve the OpenID Connect well-known file on the following web server URLs:
    /.well-known/openid-configuration
    /.well-known/oauth-configuration

The well-known file is a JSON document that describes the OpenID Connect and OAuth 2.0 endpoints. 
The contents are mostly a static configuration, but some paths depend on the web server domain, for example.
"""


class WellKnown:
    @cherrypy.expose(alias=["openid_configuration", "oauth_configuration"])
    @cherrypy.tools.json_out()
    def index(self):
        return {
            "issuer": f"{cherrypy.request.base}/idp",
            "authorization_endpoint": f"{cherrypy.request.base}/idp/auth?{TraditionalAuthorizationRequestTestSet.DUMMY_PARAMETER}=42",
            "token_endpoint": f"{cherrypy.request.base}/idp/token",
            "userinfo_endpoint": f"{cherrypy.request.base}/idp/userinfo",
            "pushed_authorization_request_endpoint": f"{cherrypy.request.base}/idp/push_auth",
            "jwks_uri": f"{cherrypy.request.base}/idp/jwks",
            "scopes_supported": ["openid"],
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code"],
            "acr_values_supported": [
                "https://www.yes.com/acrs/online_banking",
                "https://www.yes.com/acrs/online_banking_sca",
            ],
            "id_token_signing_alg_values_supported": ["RS256"],
            "userinfo_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["plain", "S256"],
            "token_endpoint_auth_methods_supported": ["self_signed_tls_client_auth"],
            "request_parameter_supported": True,
            "request_uri_parameter_supported": True,
            "require_request_uri_registration": True,
            "authorization_response_iss_parameter_supported": True,
            "tls_client_certificate_bound_access_tokens": True,
            "authorization_data_types_supported": ["payment_initiation", "sign"],
            "verification_methods_supported": [
                {
                    "identity_document": [
                        "Physical In-Person Proofing (bank)",
                        "Physical In-Person Proofing (shop)",
                        "Physical In-Person Proofing (courier)",
                        "Supervised remote In-Person Proofing",
                    ]
                },
                "qes",
                "eID",
            ],
            "claim_types_supported": ["normal"],
            "claims_supported": ["sub"] + YES_CLAIMS.keys(),
            "claims_parameter_supported": True,
            "verified_claims_supported": True,
            "trust_frameworks_supported": ["de_aml"],
            "evidence_supported": ["id_document"],
            "documents_supported": [
                "idcard",
                "passport",
                "de_idcard_foreigners",
                "de_emergency_idcard",
                "de_erp",
                "de_erp_replacement_idcard",
                "de_idcard_refugees",
                "de_idcard_apatrids",
                "de_certificate_of_suspension_of_deportation",
                "de_permission_to_reside",
                "de_replacement_idcard",
            ],
            "documents_methods_supported": ["pipp", "sripp"],
            "claims_in_verified_claims_supported": YES_VERIFIED_CLAIMS.keys(),
        }


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
        Root(
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
        CADIDP(
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
