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

from cadi.rptests.token import TokenRequestTestSet

from .platform_api import PlatformAPI
from .rptestmechanics import RPTestResultStatus
from .rptests.par import PARRequestURIAuthorizationRequestTestSet
from .rptests.traditional import TraditionalAuthorizationRequestTestSet
from .tools import CLIENT_ID_PATTERN


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
    MAX_OPEN_SESSIONS_PER_CLIENT = 10
    SESSION_EXPIRATION = 60 * 60 * 3  # 3 hours
    TEST_RESULT_EXPIRATION = 60 * 60 * 12  # 12 hours
    MAX_RETRIES_CHECK_AND_SET = 12

    def __init__(self, platform_api: PlatformAPI, cache: MemcacheClient, j2env):
        self.platform_api = platform_api
        self.cache = cache
        self.j2env = j2env

    @cherrypy.expose
    def auth(self, *args, **kwargs):
        client_id = self._desperately_find_client_id(kwargs, cherrypy.request)
        if not client_id:
            raise cherrypy.HTTPError(
                400,
                "Missing client_id! We looked for it in the URL and the request body, but we couldn't find it.",
            )

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
            # Store the session in the list of sessions for the client_id in the cache
            key = "sessions_" + client_id
            self._insert_into_cache_list(
                key,
                test.data["session"],
                self.MAX_OPEN_SESSIONS_PER_CLIENT,
                self.SESSION_EXPIRATION,
            )
            session_id = test.data["session"].sid
        else:
            session_id = None

        # Render the auth_ep.html template
        template = self.j2env.get_template("auth_ep.html")
        return template.render(
            client_id=client_id,
            test_results=test_results,
            stats=test_results.get_stats(),
            session_id=session_id,
            Status=RPTestResultStatus,
            SM=TEST_RESULT_STATUS_MAPPING,
        )

    @cherrypy.expose
    def auth_continue(self, client_id, sid):
        # Check if a session with this sid exists for the given client_id
        key = "sessions_" + client_id
        the_list = self.cache.get(key)
        if the_list is None:
            raise cherrypy.HTTPError(
                400,
                "No sessions for this client ID exist. Please start a new authorization session.",
            )

        # Check if the session with the given sid exists in the list
        for s in the_list:
            if s.sid == sid:
                session = s
                break
        else:
            raise cherrypy.HTTPError(
                400,
                "No session with this sid exists for this client ID. Please start a new authorization session.",
            )

        # Use furl library to assemble the redirect URI with the redirect URI from the session.
        # Parameters: state, code, and iss
        redirect_uri = furl(session.redirect_uri)
        if session.state is not None:
            redirect_uri.args["state"] = session.state
        redirect_uri.args["code"] = session.code
        redirect_uri.args["iss"] = "{}/idp".format(cherrypy.request.base)

        # Redirect browser to redirect_uri
        raise cherrypy.HTTPRedirect(redirect_uri.url)

    @cherrypy.expose
    def token(self, *args, **kwargs):
        client_id = self._desperately_find_client_id(kwargs, cherrypy.request)
        if not client_id:
            raise cherrypy.HTTPError(
                400,
                "Missing client_id! We looked for it in the URL and the request body, but we couldn't find it.",
            )

        # Retrieve all existing sessions to match code against
        key = "sessions_" + client_id
        client_sessions = self.cache.get(key, default=[])

        test = TokenRequestTestSet(
            self.platform_api,
            cache=self.cache,
            request=cherrypy.request,
            client_sessions=client_sessions,
            expected_client_id=client_id,
        )
        

    def _attach_test_results(self, client_id, test_results):
        key = "test_results_" + client_id
        self._insert_into_cache_list(
            key, test_results, self.MAX_TEST_RESULTS, self.TEST_RESULT_EXPIRATION
        )

    def _insert_into_cache_list(self, key, item, max_entries, expire):
        for i in range(
            self.MAX_RETRIES_CHECK_AND_SET
        ):  # Retry loop, probably it should be limited to some reasonable retries
            the_list, cas_key = self.cache.gets(key)
            if the_list is None:
                the_list = [item]
                self.cache.set(key, the_list, expire=expire)
                return
            else:
                # Insert latest result on the top
                the_list.insert(0, item)

                # Truncate the list to the max number of results
                the_list = the_list[:max_entries]

                if self.cache.cas(key, the_list, expire=expire, cas=cas_key):
                    return

        raise Exception("Could not insert data item into cache")

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
            "issuer": "{}/idp".format(cherrypy.request.base),
            "authorization_endpoint": "{}/idp/auth?predefined_parameter=1".format(
                cherrypy.request.base
            ),
            "token_endpoint": "{}/idp/token".format(cherrypy.request.base),
            "userinfo_endpoint": "{}/idp/userinfo".format(cherrypy.request.base),
            "pushed_authorization_request_endpoint": "{}/idp/push_auth".format(
                cherrypy.request.base
            ),
            "jwks_uri": "{}/idp/jwks".format(cherrypy.request.base),
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
            "claims_supported": [
                "sub",
                "email",
                "email_verified",
                "phone_number",
                "phone_number_verified",
                "given_name",
                "family_name",
                "birthdate",
                "address",
                "birth_family_name",
                "birth_middle_name",
                "birth_given_name",
                "salutation",
                "title",
                "place_of_birth",
                "gender",
                "nationalities",
                "https://www.yes.com/claims/salutation",
                "https://www.yes.com/claims/title",
                "https://www.yes.com/claims/place_of_birth",
                "https://www.yes.com/claims/nationality",
                "https://www.yes.com/claims/verified_person_data",
                "https://www.yes.com/claims/transaction_id",
                "https://www.yes.com/claims/tax_id",
                "https://www.yes.com/claims/preferred_iban",
            ],
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
            "claims_in_verified_claims_supported": [
                "given_name",
                "family_name",
                "birthdate",
                "birth_family_name",
                "birth_middle_name",
                "birth_given_name",
                "place_of_birth",
                "nationalities",
                "address",
            ],
        }


if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="CADI Server")
    parser.add_argument("platform_credentials_file", type=argparse.FileType("r"))
    args = parser.parse_args()

    # Prepare Memcache client
    cache = MemcacheClient(("localhost", 11211), serde=PickleSerde())

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
        Root(platform_api=platform_api, cache=cache, j2env=jinja2_env),
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
        CADIDP(platform_api=platform_api, cache=cache, j2env=jinja2_env),
        "/idp",
        config={"/": {"error_page.default": STATIC_PATH + "/error.html"}},
    )

    cherrypy.tree.mount(
        WellKnown(),
        "/idp/.well-known",
    )

    cherrypy.engine.start()
    cherrypy.engine.block()
