import argparse
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

import cherrypy
import cryptography
import jinja2
import requests
from cryptography import x509
from prometheus_client import Enum
from pymemcache.client.base import Client as MemcacheClient
from pymemcache.serde import PickleSerde
from yaml import SafeLoader, dump, load
from urllib.parse import parse_qs


CLIENT_ID_PATTERN = (
    r"sandbox.yes.com:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


class PlatformAPI:
    TIMEOUT = 30  # seconds
    DEFAULT_URLS = {
        "sandbox": {
            "token_endpoint": "https://as.sandbox.yes.com/token",
            "rps": "https://api.sandbox.yes.com/rps/v1/",
        },
        "production": {
            "token_endpoint": "https://as.yes.com/token",
            "rps": "https://api.yes.com/rps/v1/",
        },
    }

    def __init__(self, client_id, cert, key, environment, cache: MemcacheClient):
        self.client_id = client_id
        self.cert_pair = (cert, key)
        self.environment = environment
        self.cache = cache

    def _get_access_token(self):
        req = requests.post(
            self.DEFAULT_URLS[self.environment]["token_endpoint"],
            data={"grant_type": "client_credentials", "client_id": self.client_id},
            cert=self.cert_pair,
            timeout=self.TIMEOUT,
        )
        response = req.json()
        return response["access_token"], response["expires_in"]

    def get_client_config(self, client_id, is_retry=False):
        expire_info = None
        if not (at := self.cache.get("access_token")):
            at, expire_info = self._get_access_token()

        try:
            req = requests.get(
                self.DEFAULT_URLS[self.environment]["rps"] + f"/{client_id}",
                headers={"Authorization": f"Bearer {at}"},
                cert=self.cert_pair,
                timeout=self.TIMEOUT,
            )
            req.raise_for_status()
            # If no error was raised, and the access token was new, store it in cache.
            if expire_info:
                self.cache.set("access_token", at, expire=expire_info)
            return req.json()
        # Catch errors
        except requests.exceptions.HTTPError as e:
            # Catch 404 not found error, return None
            if e.response.status_code == 404:
                return None
            # Catch 401 unauthorized HTTP error, invalidate access token, retry.
            if e.response.status_code == 401:
                self.cache.delete("access_token")
                if is_retry:
                    raise e
                return self.get_client_config(client_id, is_retry=True)
            else:
                raise e

    def get_client_config_with_cache(self, client_id):
        # Check if this client_id is in the cache
        if not (client_config := self.cache.get(f"client_config-{client_id}")):
            # Get client configuration from directory
            try:
                client_config = self.get_client_config(client_id)
            except requests.exceptions.HTTPError as e:
                raise e
            if client_config is None:
                return None

            # Store client configuration in cache
            self.cache.set(
                f"client_config-{client_id}",
                client_config,
                expire=self.EXPIRE_CLIENT_CONFIG,
            )

        return client_config


class RPTestResultStatus(Enum):
    SUCCESS = "success"
    WARNING = "warning"
    FAILURE = "failure"
    SKIPPED = "skipped"


@dataclass
class RPTestResult:
    result: int
    text: str
    skip_all_further_tests: bool = False
    test_id: Optional[str] = None
    title: Optional[str] = None
    extra_info: Optional[str] = None
    output_data: Optional[Dict] = field(default_factory=dict)


@dataclass
class RPTestResultSet:
    request_name: str
    description: str
    test_results: List[RPTestResult]
    extra_info: Dict[str, str] = field(default_factory=dict)

    # Timestamp is set when creating the object
    timestamp: datetime = field(default_factory=datetime.utcnow)


class RPTestSet:
    PATTERN = re.compile("^t[0-9]{3}_")

    NAME: str
    INFO_BOXES: Dict[str, str] = {}

    data = {}

    def __init__(self, platform_api: PlatformAPI):
        self.platform_api = platform_api

    def run(self, **kwargs):
        # sort functions
        fns = [fn for fn in dir(self) if self.PATTERN.match(fn)]
        fns.sort()
        for fn in fns:
            print(fn)
            print(getattr(self, fn).info)
            # getattr(self, fn)(**kwargs)

    def prepare(self, **kwargs):
        pass


class ClientIDTestSet(RPTestSet):
    def t100_has_client_id(self, payload, **_):
        if not "client_id" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Client ID not found in payload.",
                skip_all_further_tests=True,
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "Client ID found in payload.",
                output_data={"client_id": payload["client_id"]},
            )

    t100_has_client_id.title = "Client ID presence in payload"

    def t101_client_id_is_valid(self, client_id, **_):
        if not re.match(CLIENT_ID_PATTERN, client_id):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Client ID does not have the right format: sandbox.yes.com:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.",
                skip_all_further_tests=True,
            )

        client_config = self.platform_api.get_client_config_with_cache(client_id)
        if client_config is None:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Client ID does not exist in directory.",
                skip_all_further_tests=True,
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Client ID was found in the yes® directory.",
            output_data={"client_config": client_config},
        )

    t101_client_id_is_valid.title = "Client ID validity"

    def t102_client_id_is_not_deactivated(self, **_):
        if self.client_config["status"] == "active":
            return RPTestResult(
                RPTestResultStatus.SUCCESS, "Client ID status is 'active'."
            )
        elif self.client_config["status"] == "inactive":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Client ID is in status 'inactive'. The client ID needs to be in status 'active' to be used. Contact yes® to fix the problem.",
                skip_all_further_tests=True,
            )
        elif self.client_config["status"] == "demo":
            return RPTestResult(
                RPTestResultStatus.WARNING,
                "Client ID is in status 'demo'. The client ID should be in status 'active' to be used. Contact yes® to fix the problem.",
            )
        else:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Client ID status is '{self.client_config['status']}'. The client ID needs to be in status 'active' to be used. Contact yes® to fix the problem.",
                skip_all_further_tests=True,
            )

    t102_client_id_is_not_deactivated.title = "Client ID status"


class ClientAuthenticationTestSet(RPTestSet):
    MTLS_HEADER = "x-yes-client-tls-certificate"

    client_certificate = None
    client_certificate_parsed = None

    def t200_client_certificate_present(self, request, **kwargs):
        if (
            not self.MTLS_HEADER in request.headers
            or request.headers[self.MTLS_HEADER] == ""
        ):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Client certificate was not presented in the TLS connection. "
                "You must ensure that your HTTP library uses your client certificate with your private key during the connection establishment to this endpoint. "
                "Note: Some libraries silently skip the use of the client certificate when the certificate or private key file cannot be found. ",
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "Some client certificate was presented in the TLS connection.",
                output_data={"client_certificate": request.headers[self.MTLS_HEADER]},
                extra_info=f"Presented client certificate:\n{request.headers[self.MTLS_HEADER]}",
            )

    t200_client_certificate_present.title = "Client certificate presence"

    def t201_client_certificate_format(self, client_certificate, **_):
        # Check if the client certificate is a valid x509 self-signed certificate
        try:
            cert = cryptography.x509.load_pem_x509_certificate(
                client_certificate.encode(), cryptography.default_backend()
            )
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "Client certificate is a valid x509 certificate.",
                output_data={"client_certificate_parsed": cert},
            )
        except Exception as e:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Client certificate is not a valid x509 certificate.",
                extra_info=str(e),
            )

    t201_client_certificate_format.title = "Client certificate format"

    def t202_client_certificate_valid(self, client_certificate_parsed, **_):
        # Check if the client certificate is a valid x509 self-signed certificate
        try:
            issuer = dict(client_certificate_parsed.get_issuer().get_components())
            subject = dict(client_certificate_parsed.get_subject().get_components())
            if (
                issuer["CN"] == subject["CN"]
                and issuer["O"] == subject["O"]
                and issuer["OU"] == subject["OU"]
                and issuer["C"] == subject["C"]
            ):
                return RPTestResult(
                    RPTestResultStatus.SUCCESS,
                    "Client certificate is a valid self-signed x509 certificate.",
                )
        except Exception as e:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Client certificate is not a valid x509 self-signed certificate.",
                extra_info=str(e),
            )

    t202_client_certificate_valid.title = "Client certificate validity"

    def t203_client_certificate_matching(self, client_config, client_certificate, **_):
        # Compare the client certificate presented to the client certificates in the 'jwks' set of the client configuration. At least one must match.
        # The client configuration jwks contains the client certificate in PEM format in the x5c member of the JWKS.

        valid_client_certificates = client_config["jwks"]
        for valid_client_certificate in valid_client_certificates:
            if valid_client_certificate["x5c"][0] == client_certificate:
                return RPTestResult(
                    RPTestResultStatus.SUCCESS,
                    "Client certificate matches one of the registered client certificates.",
                )

        return RPTestResult(
            RPTestResultStatus.FAILURE,
            "Client certificate does not match any of the registered client certificates.",
            extra_info=f"Valid client certificates:\n{valid_client_certificates}",
        )

    t203_client_certificate_matching.title = "Client certificate registered"

    def t204_client_certificate_is_not_expired(self, client_certificate_parsed, **_):
        # Check if the client certificate is not expired
        if client_certificate_parsed.not_valid_after < datetime.datetime.utcnow():
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Client certificate is expired (not valid after = {client_certificate_parsed.not_valid_after}).",
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS, "Client certificate is not expired."
            )

    t204_client_certificate_is_not_expired.title = "Client certificate expiration"


class AuthorizationRequestTestSet(RPTestSet):
    def t299_request_url_valid(self, **_):
        pass

    def t300_required_parameters_present(self, **_):
        pass

    def t301_redirect_uri_valid(self, **_):
        pass

    def t302_scope_valid(self, **_):
        pass

    def t303_response_type_valid(self, **_):
        pass

    def t304_acr_values_valid(self, **_):
        pass

    def t305_state_value_not_reused(self, **_):
        pass

    def t306_nonce_value_valid(self, **_):
        pass

    def t307_pkce_challende_valid(self, **_):
        pass

    def t308_pkce_method_valid(self, **_):
        pass

    def t309_security_features_used(self, **_):
        pass

    def t310_claims_valid(self, **_):
        pass

    def t311_claims_within_allowed_claims(self, **_):
        pass

    def t312_no_extra_parameters(self, **_):
        pass


class POSTRequestTestSet(RPTestSet):
    def t000_is_post_request(self, request, **_):
        # request is a cherrypy.request object
        if request.method != "POST":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request method is not POST. This endpoint only accepts POST requests.",
                skip_all_further_tests=True,
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS, "The request method is POST."
            )

    t000_is_post_request.title = "Request method"


class PushedAuthorizationRequestTestSet(
    POSTRequestTestSet,
    AuthorizationRequestTestSet,
    ClientIDTestSet,
    ClientAuthenticationTestSet,
):
    def t001_mime_type_is_json(self, request, **_):
        # request is a cherrypy.request object
        if "Content-Type" not in request.headers:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request does not contain a Content-Type header.",
            )

        if request.headers["Content-Type"] != "application/json":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The Content-Type header is not application/json, but '{request.headers['Content-Type']}'. This endpoint only accepts JSON requests. "
                "If you're sending JSON, you might need to set the 'Content-Type' header to the correct value.",
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "The Content-Type header is application/json.",
            )

    t001_mime_type_is_json.title = "Content-Type header"

    def t002_has_valid_json_body(self, request, **_):
        # check that the body of the request is valid JSON
        try:
            payload = json.loads(request.body.decode("utf-8"))
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "The request body is valid JSON.",
                output_data={"payload": payload},
            )
        except Exception as e:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request body is not valid JSON.",
                extra_info=str(e),
            )

    t002_has_valid_json_body.title = "JSON Request body"


class GETRequestTestSet(RPTestSet):
    def t000_is_get_request(self, request, **_):
        # request is a cherrypy.request object
        if request.method != "GET":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request method is not GET. This endpoint only accepts GET requests.",
                skip_all_further_tests=True,
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS, "The request method is GET."
            )

    t000_is_get_request.title = "Request method"

    def t001_request_url_assembled_correctly(self, request, **_):
        # request is a cherrypy.request object
        # check that the URL (cherrypy.request.query_string) is a valid form-encoded URL and does not contain parameters of the form '?n=true?foo=bar'

        if "?" in request.query_string:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The request URL does not seem to be formatted correctly. This endpoint only accepts properly encoded URLs. The part '{request.query_string}' must not contain a question mark.",
            )

        try:
            parsed = parse_qs(
                request.query_string, strict_parsing=True, errors="strict"
            )
        except Exception as e:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The request URL does not seem to be formatted correctly. This endpoint only accepts properly encoded URLs. The part '{request.query_string}' must be a valid form-encoded URL.",
                extra_info=str(e),
            )

        # ensure that in the parsed dict, each field only contains one value
        for key, value in parsed.items():
            if len(value) != 1:
                return RPTestResult(
                    RPTestResultStatus.FAILURE,
                    f"Each parameter must only be sent once. The parameter '{key}' is sent {len(value)} times.",
                )

        # use the first instance of each parameter in the output payload dict
        payload = {key: value[0] for key, value in parsed.items()}

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The request URL is properly formatted.",
            output_data={"payload": payload},
        )

    t001_request_url_assembled_correctly.title = "Request URL"


class TraditionalAuthorizationRequestTestSet(
    GETRequestTestSet, AuthorizationRequestTestSet
):
    NAME = "RFC6749 Authorization Request"


class PARRequestURIAuthorizationRequestTestSet(GETRequestTestSet):
    def t002_has_request_uri_parameter(self, payload, **_):
        if not "request_uri" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request does not contain a 'request_uri' parameter.",
            )

    def t003_request_uri_parameter_is_valid(self, **_):
        pass


class CADIDP:
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

        return print("OK")

    def _desperately_find_client_id(self, parameters, request):
        # Check if the client ID is in the URL or the form-encoded body
        if "client_id" in parameters:
            return parameters["client_id"]

        # try to decode the body if it is json and extract the client_id
        try:
            body = request.body.read().decode("utf-8")
            try:
                payload = json.loads(body)
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
    EXPIRE_CLIENT_CONFIG = 3600

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
        template = self.j2env.get_template("index.html.j2")
        return template.render(
            client_id=client_id,
            error=error,
        )

    @cherrypy.expose
    def log(self, client_id):
        client_config = self._get_client_config(client_id)

        # Render the index.html.j2 template
        template = self.j2env.get_template("log.html.j2")
        return template.render(
            client_id=client_id,
            client_config=client_config,
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
            "issuer": "{}/idp/".format(cherrypy.request.base),
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
    TEMPLATE_PATH = os.path.abspath(os.path.dirname(__file__)) + "/templates"
    jinja2_env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATE_PATH),
        autoescape=True,
    )

    # Start CherryPy server
    STATIC_PATH = os.path.abspath(os.path.dirname(__file__)) + "/static"
    cherrypy.tree.mount(
        Root(platform_api=platform_api, cache=cache, j2env=jinja2_env),
        "/",
        config={
            "/": {
                "tools.staticdir.on": True,
                "tools.staticdir.dir": STATIC_PATH,
                "tools.staticdir.index": "index.html",
                'error_page.default': STATIC_PATH + "/error.html"
            },
        },
    )

    cherrypy.tree.mount(
        CADIDP(platform_api=platform_api, cache=cache, j2env=jinja2_env),
        "/idp",
        config={
            "/": {
                'error_page.default': STATIC_PATH + "/error.html"
            }
        }
    )

    cherrypy.tree.mount(
        WellKnown(),
        "/idp/.well-known",
    )

    cherrypy.engine.start()
    cherrypy.engine.block()
