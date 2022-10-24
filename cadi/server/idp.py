import json
import re
import time
from datetime import datetime

import cherrypy
from cadi.idp.ekyc import YES_CLAIMS, YES_VERIFIED_CLAIMS, ClaimsProvider
from cadi.idp.session import SessionManager
from cadi.manualtests import RP_MANUAL_TESTS, RPManualTest
from cadi.rptestmechanics import RPTestResultStatus
from cadi.rptests.token import TokenRequestTestSet
from cadi.rptests.userinfo import UserinfoRequestTestSet
from cadi.server.userinterface import TEST_RESULT_STATUS_MAPPING
from furl import furl
from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWK

from ..rptests.par import (
    PARRequestURIAuthorizationRequestTestSet,
    PushedAuthorizationRequestTestSet,
)
from ..rptests.traditional import TraditionalAuthorizationRequestTestSet
from ..tools import (
    CLIENT_ID_PATTERN,
    get_base_url,
    json_handler,
    jwk_to_jwks,
    ACRValues,
)


def slug(text):
    return re.sub(r"[^\w-]", "", text).strip().lower()


class IDP:
    MAX_TEST_RESULTS = 15
    TEST_RESULT_EXPIRATION = 60 * 60 * 24 * 3  # 3 days
    MAX_RETRIES_CHECK_AND_SET = 12
    ID_TOKEN_LIFETIME = 3600
    INVALID = "__INVALID__"
    INVALID_ISSUER = "https://testidp.sandbox.yes.com/issuer/10000009"

    def __init__(
        self,
        platform_api,
        cache,
        j2env,
    ):
        self.platform_api = platform_api
        self.cache = cache
        self.j2env = j2env
        self.session_manager = SessionManager(cache)
        self.claims_provider = ClaimsProvider()
        self.server_jwk = self.create_new_jwk()
        self.server_jwk_invalid = self.create_new_jwk()

    def get_issuer(self):
        return get_base_url() + "/idp"

    def create_new_jwk(self):
        jwk = JWK.generate(kty="RSA", size=2048)
        return jwk

    @cherrypy.expose
    @cherrypy.tools.json_out(handler=json_handler)
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
            cherrypy.response.status = 400
            return {
                "error": "server_error",
                "error_description": "We were not able to complete your request. "
                f"Please check the logs available at {get_base_url()}/logs?client_id={client_id} for any errors.",
            }

        else:
            cherrypy.response.status = 201
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
            session = test.data["session"]
            session_id = test.data["session"].sid
        else:
            session = None
            session_id = None

        users_list = self.claims_provider.get_all_users()

        def is_runnable(manual_test: RPManualTest):
            if not session:
                return False
            if manual_test.requires is None:
                return True
            return manual_test.requires(session)

        # Render the auth_ep.html template
        template = self.j2env.get_template("auth_ep.html")
        return template.render(
            client_id=client_id,
            test_results=test_results,
            stats=test_results.get_stats(),
            session_id=session_id,
            is_runnable=is_runnable,
            Status=RPTestResultStatus,
            SM=TEST_RESULT_STATUS_MAPPING,
            users_list=users_list,
            manual_tests=RP_MANUAL_TESTS,
            slug=slug,
        )

    @cherrypy.expose
    def auth_continue(
        self,
        client_id,
        sid,
        user_id=None,
        test_case=None,
        id_token_content_selector=None,
        id_token_content_left=None,
        id_token_content_right=None,
        userinfo_content_selector=None,
        userinfo_content_left=None,
        userinfo_content_right=None,
    ):
        session = self.session_manager.find(client_id=client_id, sid=sid)
        if session is None:
            raise cherrypy.HTTPError(
                400,
                "No session with this sid exists for this client ID. Please start a new authorization session.",
            )

        if test_case == "m000_custom_user_details":
            # redirect to auth_response_modifications
            return self._auth_response_modifications(
                client_id,
                sid,
                user_id,
            )

        if not user_id and not test_case:
            assert id_token_content_selector
            assert id_token_content_left
            assert id_token_content_right
            assert userinfo_content_selector
            assert userinfo_content_left
            assert userinfo_content_right

            if id_token_content_selector == "left":
                session.id_token_response_contents = json.loads(id_token_content_left)
            else:
                session.id_token_response_contents = json.loads(id_token_content_right)

            if userinfo_content_selector == "left":
                session.userinfo_response_contents = json.loads(userinfo_content_left)
            else:
                session.userinfo_response_contents = json.loads(userinfo_content_right)

        else:
            session.id_token_response_contents = (
                self.claims_provider.process_ekyc_request(
                    user_id, session, "id_token", False
                )
            )

            session.userinfo_response_contents = (
                self.claims_provider.process_ekyc_request(
                    user_id, session, "userinfo", False
                )
            )

        session.code_issued_at = datetime.utcnow()
        session.test_case = test_case
        self.session_manager.store(session)
        self._send_authorization_response(session)

    def _send_authorization_response(self, session):
        # Use furl library to assemble the redirect URI with the redirect URI from the session.
        # Parameters: state, code, and iss, or error parameters
        redirect_uri = furl(session.redirect_uri)
        if session.state is not None:
            redirect_uri.args["state"] = session.state + (
                self.INVALID if session.test_case == "m210_state_is_wrong" else ""
            )

        if session.test_case != "m201_iss_is_missing":
            if session.test_case == "m200_iss_is_wrong":
                issuer = self.INVALID_ISSUER
            elif session.test_case == "m202_iss_twice":
                issuer = [self.get_issuer(), self.INVALID_ISSUER]
            else:
                issuer = self.get_issuer()

            redirect_uri.args["iss"] = issuer

        if session.test_case == "m800_user_aborts":
            redirect_uri.args["error"] = "access_denied"
            redirect_uri.args[
                "error_description"
            ] = "Test: User aborted the authorization"
        elif session.test_case == "m810_select_different_bank":
            redirect_uri.args["error"] = "account_selection_requested"
        elif session.test_case == "m820_technical_error":
            redirect_uri.args["error"] = "server_error"
            redirect_uri.args["error_description"] = "Test: Technical error"
        else:
            redirect_uri.args["code"] = session.authorization_code

        # Redirect browser to redirect_uri
        raise cherrypy.HTTPRedirect(redirect_uri.url)

    def _auth_response_modifications(self, client_id, sid, user_id):
        session = self.session_manager.find(client_id=client_id, sid=sid)
        if session is None:
            raise cherrypy.HTTPError(
                400,
                "No session with this sid exists for this client ID. Please start a new authorization session.",
            )

        response_id_token_normal = json.dumps(
            self.claims_provider.process_ekyc_request(
                user_id, session, "id_token", False
            ),
            indent=2,
        )
        response_id_token_minimal = json.dumps(
            self.claims_provider.process_ekyc_request(
                user_id, session, "id_token", True
            ),
            indent=2,
        )
        response_userinfo_normal = json.dumps(
            self.claims_provider.process_ekyc_request(
                user_id, session, "userinfo", False
            ),
            indent=2,
        )
        response_userinfo_minimal = json.dumps(
            self.claims_provider.process_ekyc_request(
                user_id, session, "userinfo", True
            ),
            indent=2,
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
    @cherrypy.tools.json_out(handler=json_handler)
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

        test_results = test.run()
        self._attach_test_results(client_id, test_results)

        if "session" not in test.data:
            cherrypy.response.status = 400
            return {
                "error": "server_error",
                "error_description": "We were unable to identify the session to which your request belongs. "
                "Please ensure that your token request is conformant to the token request format defined in RFC6749! "
                f"Please check the logs available at {get_base_url()}/logs?client_id={client_id} for any errors.",
            }

        session = test.data["session"]

        response = {
            "access_token": session.access_token,
            "token_type": "Bearer",
            "expires_in": SessionManager.SESSION_EXPIRATION,
        }

        if "openid" in session.scopes_list:
            response["id_token"] = self._create_id_token(
                session,
                test_invalid_nonce=(session.test_case == "m110_id_token_nonce"),
                test_expired=(session.test_case == "m120_id_token_expired"),
                test_aud_wrong=(session.test_case == "m130_id_token_aud_wrong"),
                test_iss_wrong=(session.test_case == "m131_id_token_iss_wrong"),
                test_wrong_key=(
                    session.test_case == "m140_id_token_signature_using_wrong_key"
                ),
                test_alg_is_none=(
                    session.test_case == "m150_id_token_signature_alg_is_none"
                ),
                test_acr_wrong=(session.test_case == "m300_acr_wrong"),
                test_acr_missing=(session.test_case == "m310_acr_missing"),
            )

        return response

    @cherrypy.expose
    @cherrypy.tools.json_out(handler=json_handler)
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

        client_config = self.platform_api.get_client_config_with_cache(client_id)

        test = UserinfoRequestTestSet(
            platform_api=self.platform_api,
            cache=self.cache,
            client_id=client_id,
            request=cherrypy.request,
            session=session,
            client_config=client_config,
        )

        test_results = test.run()
        self._attach_test_results(client_id, test_results)

        return session.userinfo_response_contents

    @cherrypy.expose
    @cherrypy.tools.json_out(handler=json_handler)
    def jwks(self):
        # JWKS Endpoint: Serve the server certificate
        return jwk_to_jwks(self.server_jwk)

    def _attach_test_results(self, client_id, test_results):
        key = ("test_results", client_id)
        self.cache.insert_into_list(
            key,
            test_results,
            self.MAX_TEST_RESULTS,
            self.TEST_RESULT_EXPIRATION,
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

    def _create_id_token(
        self,
        session,
        test_invalid_nonce,
        test_expired,
        test_aud_wrong,
        test_iss_wrong,
        test_wrong_key,
        test_alg_is_none,
        test_acr_wrong,
        test_acr_missing,
    ):
        claims = session.id_token_response_contents

        # Issuer
        claims["iss"] = self.INVALID_ISSUER if test_iss_wrong else self.get_issuer()

        # Audience
        claims["aud"] = session.client_id + (self.INVALID if test_aud_wrong else "")

        # Issued at and Expiration
        make_expired = -(self.ID_TOKEN_LIFETIME * 2) if test_expired else 0
        claims["iat"] = int(time.time()) + make_expired
        claims["exp"] = int(time.time()) + self.ID_TOKEN_LIFETIME + make_expired

        # Nonce - if provided
        if session.nonce:
            claims["nonce"] = session.nonce + (
                self.INVALID if test_invalid_nonce else ""
            )

        # ACR Value - if requested
        if session.acr_values_list and not test_acr_missing:
            if test_acr_wrong:
                claims["acr"] = ACRValues.DEFAULT
            else:
                if ACRValues.SCA in session.acr_values_list:
                    claims["acr"] = ACRValues.SCA
                else:
                    claims["acr"] = ACRValues.DEFAULT

        # Create a signed ID token using the server's private key
        id_token = JWT(
            header={"kid": "default", "alg": "none" if test_alg_is_none else "RS256"},
            claims=claims,
            key=self.server_jwk_invalid if test_wrong_key else self.server_jwk,
            algs=["RS256", "none"],
        )
        id_token.make_signed_token(
            self.server_jwk_invalid if test_wrong_key else self.server_jwk
        )
        return id_token.serialize()

    @staticmethod
    def json_error_page(status, message, traceback, version):
        cherrypy.response.headers["Content-Type"] = "application/json"
        return json.dumps(
            {
                "error_description": f"Error while processing your message: {message}",
                "error": "server_error",
            }
        )


"""
Serve the OpenID Connect well-known file on the following web server URLs:
    /.well-known/openid-configuration
    /.well-known/oauth-configuration

The well-known file is a JSON document that describes the OpenID Connect and OAuth 2.0 endpoints. 
The contents are mostly a static configuration, but some paths depend on the web server domain, for example.
"""


class WellKnown:
    @cherrypy.expose(alias=["openid_configuration", "oauth_authorization_server"])
    @cherrypy.tools.json_out(handler=json_handler)
    def index(self):
        return {
            "issuer": f"{get_base_url()}/idp",
            "authorization_endpoint": f"{get_base_url()}/idp/auth?{TraditionalAuthorizationRequestTestSet.DUMMY_PARAMETER}=42",
            "token_endpoint": f"{get_base_url()}/idp/token",
            "userinfo_endpoint": f"{get_base_url()}/idp/userinfo",
            "pushed_authorization_request_endpoint": f"{get_base_url()}/idp/par",
            "jwks_uri": f"{get_base_url()}/idp/jwks",
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
            "claims_supported": ["sub"] + list(YES_CLAIMS.keys()),
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
            "claims_in_verified_claims_supported": list(YES_VERIFIED_CLAIMS.keys()),
            "subject_types_supported": ["public", "pairwise"],
        }
