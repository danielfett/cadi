from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import os
import re
from typing import Dict, List, Optional
from urllib.parse import parse_qs

import cryptography
import jsonschema

from .tools import CLIENT_ID_PATTERN


class References:
    RFC6749 = "https://tools.ietf.org/html/rfc6749"


class RPTestResultStatus(Enum):
    SUCCESS = "success"
    WARNING = "warning"
    FAILURE = "failure"
    SKIPPED = "skipped"
    INFO = "info"
    WAITING = "waiting"


@dataclass
class RPTestResult:
    result: str
    text: str
    skip_all_further_tests: bool = False
    test_id: Optional[str] = None
    title: Optional[str] = None
    extra_info: Dict[str, str] = field(default_factory=dict)
    output_data: Optional[Dict] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    service_information: Optional[Dict] = field(default_factory=dict)


@dataclass
class RPTestResultSet:
    request_name: str
    description: str
    test_results: List[RPTestResult]
    extra_info: Dict[str, str] = field(default_factory=dict)
    service_information: Optional[Dict] = field(default_factory=dict)

    # Timestamp is set when creating the object
    timestamp: datetime = field(default_factory=datetime.utcnow)


SCHEMAS_PATH = os.path.abspath(os.path.dirname(__file__)) + "/../schemas"


def validate_with_json_schema(json_input, schema_filename):
    schema_path = os.path.join(SCHEMAS_PATH, schema_filename)
    with open(schema_path) as f:
        schema = json.load(f)
    try:
        jsonschema.validate(json_input, schema)
    except jsonschema.ValidationError as e:
        return False, str(e)
    return True, None


"""
An RP Test Set contains functions of the form t1234_ that are called by the
run() method in the lexical order of the function names. The number therefore
defines the order of the tests.

The convention for the number is as follows:
 * the first digit is the class of the test (0=basic request, 1=identifying the
   calling client, 2=client authentication, 3..=content checks)
 * the second and third digits can be used to group the tests (e.g., all tests
   around the claims parameter)
 * the fourth digit is the test number within the group
"""


class RPTestSet:
    TEST_NAME_PATTERN = re.compile("^t[0-9]{4}_")

    NAME: str
    DESCRIPTION: str

    # data is a dict holding data to be persisted between tests
    data: Dict
    extra_info: Dict[str, str] = {}
    service_information: Optional[Dict] = {}

    def __init__(self, platform_api, cache, **data):
        self.platform_api = platform_api
        self.cache = cache
        self.data = data

    def run(self):
        # Sort tXXX_* functions
        test_function_names = sorted(
            [
                function_name
                for function_name in dir(self)
                if self.TEST_NAME_PATTERN.match(function_name)
            ]
        )

        # We collect test results in an array to later produce an RPTestResultSet
        test_results = []

        # Run all functions
        skip_all_further_tests = False
        for function_name in test_function_names:
            # fn is the actual function object
            fn = getattr(self, function_name)

            # If skip_all_further_tests is set, the test is not run, but an empty test result is created.
            # If not all required data values are available, the test is skipped as well.
            if skip_all_further_tests or not self._all_data_available(fn):
                # Create empty test result
                result = RPTestResult(
                    result=RPTestResultStatus.SKIPPED,
                    text="Test skipped: An earlier test failed or this test is not relevants.",
                )
            else:
                # Actually run test
                result = fn(**self.data)
                if result is None:
                    result = RPTestResult(
                        result=RPTestResultStatus.SKIPPED,
                        text="Test returned no result.",
                    )

            # Augment result data with information from the test function
            result.test_id = function_name
            result.title = getattr(fn, "title", function_name)
            result.references = getattr(fn, "references", [])

            # Update the data with the result
            self.data.update(result.output_data)
            self.extra_info.update(result.extra_info)
            self.service_information.update(result.service_information)
            if result.skip_all_further_tests:
                skip_all_further_tests = True

            # Add result to the list of test results
            test_results.append(result)

        # Create RPTestResultSet
        return RPTestResultSet(
            request_name=self.NAME,
            description=self.DESCRIPTION,
            test_results=test_results,
            extra_info=self.extra_info,
            service_information=self.service_information,
        )

    def _all_data_available(self, fn):
        required_data = fn.__code__.co_varnames[
            1 : fn.__code__.co_argcount
        ]  # skip self
        for varname in required_data:
            if varname == "_":
                continue
            if varname not in self.data:
                print(f"{fn}: Missing required data value {varname}")
                return False
        return True

    def prepare(self, **kwargs):
        pass


class ClientIDTestSet(RPTestSet):
    def t1000_has_client_id(self, payload, **_):
        if not "client_id" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Client ID not found in payload. The parameter 'client_id' was expected.",
                skip_all_further_tests=True,
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "The 'client_id' parameter was found in the payload.",
                output_data={"client_id": payload["client_id"]},
            )

    t1000_has_client_id.title = "Client ID presence in payload"

    def t1001_client_id_is_valid(self, client_id, **_):
        if not re.match(CLIENT_ID_PATTERN, client_id):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Client ID '{client_id}' does not have the right format: sandbox.yes.com:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.",
                skip_all_further_tests=True,
            )

        client_config = self.platform_api.get_client_config_with_cache(client_id)
        if client_config is None:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Client ID '{client_id}' does not exist in the yes directory.",
                skip_all_further_tests=True,
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"Client ID '{client_id}' is of the correct format and was found in the yes® directory.",
            output_data={"client_config": client_config},
        )

    t1001_client_id_is_valid.title = "Client ID validity"

    def t1002_client_id_is_not_deactivated(self, client_config, **_):
        if client_config["status"] == "active":
            return RPTestResult(
                RPTestResultStatus.SUCCESS, "Client ID status is 'active'."
            )
        elif client_config["status"] == "inactive":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Client ID is in status 'inactive'. The client ID needs to be in status 'active' to be used. Contact yes® to fix the problem.",
                skip_all_further_tests=True,
            )
        elif client_config["status"] == "demo":
            return RPTestResult(
                RPTestResultStatus.WARNING,
                "Client ID is in status 'demo'. The client ID should be in status 'active' to be used. Contact yes® to fix the problem.",
            )
        else:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Client ID status is '{client_config['status']}'. The client ID needs to be in status 'active' to be used. Contact yes® to fix the problem.",
                skip_all_further_tests=True,
            )

    t1002_client_id_is_not_deactivated.title = "Client ID status"


class ClientAuthenticationTestSet(RPTestSet):
    MTLS_HEADER = "x-yes-client-tls-certificate"

    client_certificate = None
    client_certificate_parsed = None

    def t2000_client_certificate_present(self, request, **kwargs):
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

    t2000_client_certificate_present.title = "Client certificate presence"

    def t2001_client_certificate_format(self, client_certificate, **_):
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
                "Client certificate is not a valid x509 certificate. "
                "Please see the yes® Developer Guide on how to create a certificate suitable for the ues with yes®.",
                extra_info=str(e),
            )

    t2001_client_certificate_format.title = "Client certificate format"
    t2001_client_certificate_format.references = [
        (
            "yes® Relying Party Developer Guide, Onboarding and Testing, Section 4.1",
            "https://yes.com/docs/rp-devguide/latest/ONBOARDING/index.html#_required_data",
        ),
    ]

    def t2002_client_certificate_valid(self, client_certificate_parsed, **_):
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
                "Client certificate is not a valid x509 self-signed certificate. "
                "Please see the yes® Developer Guide on how to create a self-signed certificate.",
                extra_info=str(e),
            )

        return RPTestResult(
            RPTestResultStatus.FAILURE,
            "Client certificate is not a valid x509 self-signed certificate. "
            "Please see the yes® Developer Guide on how to create a self-signed certificate.",
        )

    t2002_client_certificate_valid.title = "Client certificate validity"
    t2002_client_certificate_valid.references = [
        (
            "yes® Relying Party Developer Guide, Onboarding and Testing, Section 4.1",
            "https://yes.com/docs/rp-devguide/latest/ONBOARDING/index.html#_required_data",
        ),
    ]

    def t2003_client_certificate_matching(self, client_config, client_certificate, **_):
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
            "Client certificate does not match any of the registered client certificates. "
            "Please ensure that you are using the correct client certificate that has been registered with yes®.",
            extra_info=f"Valid client certificates:\n{valid_client_certificates}",
        )

    t2003_client_certificate_matching.title = "Client certificate registered"
    t2003_client_certificate_matching.references = [
        (
            "yes® Relying Party Developer Guide, Onboarding and Testing, Section 4.1",
            "https://yes.com/docs/rp-devguide/latest/ONBOARDING/index.html#_required_data",
        ),
    ]

    def t2004_client_certificate_is_not_expired(self, client_certificate_parsed, **_):
        # Check if the client certificate is not expired
        if client_certificate_parsed.not_valid_after < datetime.datetime.utcnow():
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Client certificate is expired (not valid after = {client_certificate_parsed.not_valid_after}). Please contact yes® with a new client certificate (see references).",
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS, "Client certificate is not expired."
            )

    t2004_client_certificate_is_not_expired.title = "Client certificate expiration"
    t2004_client_certificate_is_not_expired.references = [
        (
            "yes® Relying Party Developer Guide, Onboarding and Testing, Section 4.1",
            "https://yes.com/docs/rp-devguide/latest/ONBOARDING/index.html#_required_data",
        ),
    ]


class AuthorizationRequestTestSet(RPTestSet):
    NONCE_MIN_LENGTH = 20
    NONCE_RECOMMENDED_MIN_LENGTH = 32
    SEC_PARAMS_CACHE_EXPIRATION = 5 * 60

    PKCE_CODE_CHALLENGE_REGEX = re.compile(r"^[a-zA-Z0-9\-._~]{43,128}$")
    PKCE_CODE_CHALLENGE_MIN_LENGTH = 43

    def t3010_redirect_uri_valid(self, payload, client_config, **_):
        if not "redirect_uri" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Redirect URI (redirect_uri) is missing in the authorization request.",
            )

        # Check that the redirect URI exactly matches the one in the client configuration
        if payload["redirect_uri"] not in client_config["redirect_uris"]:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Redirect URI (redirect_uri) in the authorization request does not match the one in the client configuration. "
                "If you need a different redirect URI registered, please contact yes®. "
                "Note that for security reasons, all redirect URIs must match exactly a registered redirect URI.",
                extra_info=f"Redirect URI (redirect_uri) in the authorization request: {payload['redirect_uri']}\n"
                f"Redirect URIs in the client configuration: {', '.join(client_config['redirect_uris'])}",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Redirect URI (redirect_uri) parameter is present in the authorization request and the provided redirect URI matches one of the registered redirect URIs in the client configuration.",
        )

    t3010_redirect_uri_valid.title = "Redirect URI (redirect_uri)"
    t3010_redirect_uri_valid.references = [
        (
            "yes® Relying Party Developer Guide, Onboarding and Testing, Section 4.1",
            "https://yes.com/docs/rp-devguide/latest/ONBOARDING/index.html#_required_data",
        ),
    ]

    def t3020_claims_valid(self, payload, **_):
        if not "claims" in payload:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "Claims parameter (claims) is not used in the authorization request. This means that the identity service is not used.",
                output_data={"claims_parameter_provided": False},
            )

        # Check that the claims are valid according to the specification
        try:
            claims = json.loads(payload["claims"])
            if not isinstance(claims, dict):
                return RPTestResult(
                    RPTestResultStatus.FAILURE,
                    "Claims (claims) in the authorization request is not a valid JSON object.",
                )
            else:
                return RPTestResult(
                    RPTestResultStatus.SUCCESS,
                    "The claims parameter is present in the authorization request and is a valid JSON object.",
                    output_data={
                        "claims_parameter_provided": True,
                        "claims_parsed": claims,
                    },
                    service_information={
                        "Identity claims requested": str(claims),
                    },
                )
        except Exception as e:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Claims (claims) in the authorization request is not a valid JSON object.",
                extra_info=str(e),
            )

    t3020_claims_valid.title = "Usage of claims parameter"
    t3020_claims_valid.references = [
        (
            "yes® Relying Party Developer Guide, Identity Service, Section 1.4",
            "https://yes.com/docs/rp-devguide/latest/IDENTITY/index.html#_requesting_claims",
        ),
        (
            "OpenID Connect for Identity Assurance, Implementers Draft 3",
            "https://openid.net/specs/openid-connect-4-identity-assurance-1_0-ID3.html",
        ),
        (
            "OpenID Connect Core 1.0, Section 5.5",
            "https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter",
        ),
    ]

    def t3021_claims_valid(self, claims_parsed, **_):
        if not type(claims_parsed) is dict:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Claims (claims) in the authorization request is not a valid JSON object.",
            )

        # Only userinfo and id_token must be top-level elements in the claims parameter
        if not set(claims_parsed.keys()) <= {"userinfo", "id_token"}:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The claims parameter must only contain the top-level elements userinfo and id_token.",
            )

        # Test against JSON schema
        success, error = validate_with_json_schema(claims_parsed, "ekyc.json")
        if not success:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The claims parameter is not valid (see below for details).",
                extra_info=error,
            )

        # Assemble information on the claims used
        unverified_claims_requested = []
        verified_claims_requested = []
        for endpoint in ("userinfo", "id_token"):
            if not endpoint in claims_parsed:
                continue

            # first, read the unverified claims - they are directly contained below the endpoint
            for claim in claims_parsed[endpoint].keys():
                if claim == "verified_claims":
                    continue
                unverified_claims_requested.append(claim)

            # then check if verified_claims is present
            if not "verified_claims" in claims_parsed[endpoint]:
                continue

            # claims are in verified_claims/claims
            verified_claims = claims_parsed[endpoint]["verified_claims"]
            if not "claims" in verified_claims:
                continue

            # read the verified claims
            for claim in verified_claims["claims"].keys():
                verified_claims_requested.append(claim)

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The claims parameter is valid according to the specification.",
            output_data={
                "unverified_claims_requested": unverified_claims_requested,
                "verified_claims_requested": verified_claims_requested,
            },
            service_information={
                "Verified claims requested": str(verified_claims_requested),
                "Unverified claims requested": str(unverified_claims_requested),
            },
        )

    t3021_claims_valid.title = "Claims parameter format"

    def t3022_claims_within_allowed_claims(
        self, client_config, unverified_claims_requested, verified_claims_requested, **_
    ):
        # All unverified claims must be listed in the allowed_claims
        not_allowed_unverified_claims = set(unverified_claims_requested) - set(
            client_config["allowed_claims"]
        )
        not_allowed_verified_claims = set(verified_claims_requested) - set(
            client_config["allowed_claims"]
        )

        if not_allowed_unverified_claims or not_allowed_verified_claims:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Requesting the following claims is not permitted for your client: "
                + ", ".join(not_allowed_unverified_claims | not_allowed_verified_claims)
                + " To enable these claims for your client, please contact yes®.",
            )

        if (
            len(verified_claims_requested)
            and not "verified_claims" in client_config["allowed_claims"]
        ):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Requesting verified claims is not permitted for your client. "
                "Please contact yes® if you want to request verified claims.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The client is permitted to request the claims listed in the claims parameter.",
        )

    t3022_claims_within_allowed_claims.title = "Claims permissions"

    def t3030_scope_format(self, payload, **_):
        # Scope is optional, but only for non-identity flows
        if not "scope" in payload:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "Scope parameter (scope) is not used in the authorization request. This means that the identity service is not requested.",
                output_data={"scopes_list": []},
            )

        # The scope parameter must be a space-separated list of strings
        REGEX = r"^\w+( \w+)*$"
        if not re.match(REGEX, payload["scope"]):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Scope parameter (scope) is not a space-separated list of strings.",
            )

        # The scope parameter must contain 'openid' if the claims parameter is used
        scopes_list = payload["scope"].split(" ")
        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Scope parameter (scope) is provided and of the correct format.",
            output_data={"scopes_list": scopes_list},
        )

    t3030_scope_format.title = "scope parameter format"
    t3030_scope_format.references = [
        ("RFC6749, Appendix A.4", "https://tools.ietf.org/html/rfc6749#appendix-A.4"),
    ]

    def t3031_scope_matches_service_usage(
        self, scopes_list, claims_parameter_provided, **_
    ):
        if claims_parameter_provided and "openid" not in scopes_list:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Scope parameter (scope) must contain 'openid' in identity flows. "
                "Your use of the 'claims' parameter indicates that you want to use the identity flow. "
                "In this case, using 'scope=openid' is mandatory.",
                output_data={"scopes_list": scopes_list},
            )

        # If 'openid' scope is used, the claims parameter should be used as well
        if "openid" in scopes_list and not claims_parameter_provided:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                "You are using the identity service (scope contains 'openid'), but you are not using the 'claims' parameter. "
                "The claims parameter should be used to select the claims that are returned in the ID token and on the userinfo response.",
                output_data={"scopes_list": scopes_list},
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Scope parameter (scope) use matches the use case.",
            service_information={
                "Identity Service used": "yes" if ("openid" in scopes_list) else "no",
            },
        )

    t3031_scope_matches_service_usage.title = "Usage of scope parameter"
    t3031_scope_matches_service_usage.references = [
        (
            "yes® Relying Party Developer Guide, Identity Service, Section 3.2.1",
            "https://yes.com/docs/rp-devguide/latest/IDENTITY/index.html#_parameters",
        ),
    ]

    def t3032_scope_allowed_values(self, scopes_list, **_):
        # Some scopes are known, but should not be used
        SHOULD_NOT_USE = ["profile", "email", "address", "phone", "offline_access"]

        for scope in SHOULD_NOT_USE:
            if scope in scopes_list:
                return RPTestResult(
                    RPTestResultStatus.WARNING,
                    f"Scope parameter (scope) contains '{scope}' which should not be used.",
                )

        # Other scopes should not be used at all
        KNOWN = SHOULD_NOT_USE + ["openid"]

        for scope in scopes_list:
            if scope not in KNOWN:
                return RPTestResult(
                    RPTestResultStatus.WARNING,
                    f"Scope parameter (scope) contains unknown scope '{scope}'.",
                )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Scope parameter (scope) looks fine.",
        )

    t3032_scope_allowed_values.title = "Other values in scope parameter"

    def t3040_response_type_valid(self, payload, **_):
        if not "response_type" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Response type parameter (response_type) must be present in the authorization request. Set response_type=code for yes® flows.",
            )

        if payload["response_type"] != "code":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Response type parameter (response_type) must be set to 'code', but is '{payload['response_type']}'. Set response_type=code for yes® flows.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Response type parameter (response_type) is set to 'code'.",
        )

    t3040_response_type_valid.title = "response_type parameter"
    t3040_response_type_valid.references = [
        (
            "yes® Relying Party Developer Guide, Identity Service, Section 3.2.1",
            "https://yes.com/docs/rp-devguide/latest/IDENTITY/index.html#_parameters",
        ),
    ]

    def t3050_acr_values_valid(self, payload, **_):
        if not "acr_values" in payload:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "acr_values parameter is not used in the authorization request. Since it is not required, this is fine. "
                "This means that no particular authentication method (one factor or two factors) is requested from the user.",
                service_information={"Second-factor authentication": "Not requested"},
            )

        # The acr_values parameter must be a space-separated list of strings
        REGEX = r"^\w+( \w+)*$"
        if not re.match(REGEX, payload["acr_values"]):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "acr_values parameter must be a space-separated list of strings.",
            )

        # The acr_values parameter must contain 'openid' if the claims parameter is used
        acr_values_list = payload["acr_values"].split(" ")

        ACR_DEF = "https://www.yes.com/acrs/online_banking"
        ACR_2FA = "https://www.yes.com/acrs/online_banking_sca"

        for val in acr_values_list:
            if val not in [ACR_DEF, ACR_2FA]:
                return RPTestResult(
                    RPTestResultStatus.FAILURE,
                    f"acr_values parameter contains unknown value '{val}'. "
                    f"Only '{ACR_DEF}' and '{ACR_2FA}' are allowed.",
                )

        if len(acr_values_list) > 1:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                "acr_values parameter contains more than one value. "
                f"It is recommended to use only one of the allowed values ('{ACR_DEF}' or '{ACR_2FA}').",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "acr_values parameter is present in the authorization request, is of the correct format and contains a valid value.",
            service_information={
                "Second-factor authentication": "Requested"
                if ACR_2FA in acr_values_list
                else "Not requested"
            },
        )

    t3050_acr_values_valid.title = "acr_values parameter"
    t3050_acr_values_valid.references = [
        (
            "yes® Relying Party Developer Guide, Identity Service, Section 3.2.3",
            "https://yes.com/docs/rp-devguide/latest/IDENTITY/index.html#acr",
        ),
    ]

    def t3060_state_value_used(self, payload, **_):
        if not "state" in payload:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "State parameter is not used in the authorization request.",
                service_information={"State parameter": "Not used"},
            )
        else:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "State parameter is used in the authorization request.",
                service_information={"State parameter": "In use"},
            )

    t3060_state_value_used.title = "State parameter use"

    def t3070_nonce_value_valid(self, payload, scopes_list, **_):
        if not "nonce" in payload:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "Nonce parameter is not used in the authorization request.",
                service_information={"Nonce parameter": "Not used"},
                output_data={"sec_nonce_is_used": False},
            )

        nonce = payload["nonce"]
        if len(nonce) < self.NONCE_MIN_LENGTH:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Nonce parameter (nonce) is too short. It must be at least {self.NONCE_MIN_LENGTH} characters long.",
                service_information={"Nonce parameter": "In use"},
                output_data={"nonce": nonce, "sec_nonce_is_used": True},
            )

        if len(nonce) < self.NONCE_RECOMMENDED_MIN_LENGTH:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                f"Nonce parameter (nonce) is only {len(nonce)} characters long. It is recommended to use at least {self.NONCE_RECOMMENDED_MIN_LENGTH} characters long.",
                service_information={"Nonce parameter": "In use"},
                output_data={"nonce": nonce, "sec_nonce_is_used": True},
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Nonce parameter is present in the authorization request, and is long enough.",
            service_information={"Nonce parameter": "In use"},
            output_data={"nonce": nonce, "sec_nonce_is_used": True},
        )

    t3070_nonce_value_valid.title = "Nonce parameter use"

    def t3071_nonce_not_reused(self, client_id, nonce, **_):
        key = f"nonce-list-{client_id}"
        # check whether nonce matches any of the previously stored values from cache
        previous_nonces = self.cache.get(key, default=[])
        if len(previous_nonces) == 0:
            self.cache.set(key, [nonce], expire=self.SEC_PARAMS_CACHE_EXPIRATION)
            return RPTestResult(
                RPTestResultStatus.WAITING,
                f"No previous nonces found for this client ID. Repeat the authorization request within {self.SEC_PARAMS_CACHE_EXPIRATION} seconds to perform this check.",
            )

        if nonce in previous_nonces:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Repeated use of the same nonce parameter value: '{nonce}'. "
                "This is a security risk! The nonce value must be chosen randomly for each request. ",
            )

        previous_nonces.append(nonce)
        self.cache.set(key, previous_nonces, expire=self.SEC_PARAMS_CACHE_EXPIRATION)
        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"Nonce parameter value is unique within the last {len(previous_nonces)} requests. ",
            extra_info="Previously used nonces:\n" + "\n".join(previous_nonces),
        )

    t3071_nonce_not_reused.title = "Nonce parameter uniqueness"

    def t3080_pkce_use(self, payload, **_):
        if not "code_challenge" in payload and not "code_challenge_method" in payload:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "PKCE (code_challenge and code_challenge_method) is not used in the authorization request.",
                service_information={"PKCE": "Not used"},
                output_data={"sec_pkce_is_used": False},
            )

        if "code_challenge" in payload and "code_challenge_method" in payload:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "PKCE (code_challenge and code_challenge_method) is used in the authorization request.",
                service_information={"PKCE": "In use"},
                output_data={
                    "sec_pkce_is_used": True,
                    "code_challenge": payload["code_challenge"],
                    "code_challenge_method": payload["code_challenge_method"],
                },
            )

        return RPTestResult(
            RPTestResultStatus.FAILURE,
            "The PKCE parameters code_challenge and code_challenge_method must either both be used, or both be omitted.",
            service_information={"PKCE": "In use"},
            output_data={"sec_pkce_is_used": True},
        )

    t3080_pkce_use.title = "PKCE use"

    def t3081_pkce_method_valid(self, code_challenge_method, **_):
        # MUST be plain or S256, but S256 should be used
        if code_challenge_method != "S256":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The code_challenge_method parameter is set to '{code_challenge_method}'. "
                "The method 'S256' must be used instead.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The code_challenge_method parameter is set to S256.",
        )

    t3081_pkce_method_valid.title = "PKCE method"

    def t3082_pkce_parameters_valid(self, code_challenge, **_):
        # Check that code_challenge is long enough
        if len(code_challenge) < self.PKCE_CODE_CHALLENGE_MIN_LENGTH:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The code_challenge parameter is too short. It must be at least {self.PKCE_CODE_CHALLENGE_MIN_LENGTH} characters long.",
            )

        # Check that code_challenge matches the regex
        if not self.PKCE_CODE_CHALLENGE_REGEX.match(code_challenge):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The code_challenge parameter is not valid. It must match the regex '{self.PKCE_CODE_CHALLENGE_REGEX}'.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The code_challenge parameter is valid.",
        )

    t3082_pkce_parameters_valid.title = "PKCE parameter format"

    def t3083_pkce_parameter_reuse(self, client_id, code_challenge, **_):
        key = f"pkce-list-{client_id}"
        # check whether code_challenge matches any of the previously stored values from cache
        previous_code_challenges = self.cache.get(key, default=[])
        if len(previous_code_challenges) == 0:
            self.cache.set(
                key, [code_challenge], expire=self.SEC_PARAMS_CACHE_EXPIRATION
            )
            return RPTestResult(
                RPTestResultStatus.WAITING,
                f"No previous code challenges found for this client ID. Repeat the authorization request within {self.SEC_PARAMS_CACHE_EXPIRATION} seconds to perform this check.",
            )

        if code_challenge in previous_code_challenges:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Repeated use of the same code_challenge parameter value: '{code_challenge}'. "
                "This is a security risk! The code_challenge value must be chosen randomly for each request. ",
            )

        previous_code_challenges.append(code_challenge)
        self.cache.set(
            key, previous_code_challenges, expire=self.SEC_PARAMS_CACHE_EXPIRATION
        )
        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The code_challenge parameter value is unique within the last {len(previous_code_challenges)} requests. ",
            extra_info="Previously used code_challenges:\n"
            + "\n".join(previous_code_challenges),
        )

    t3083_pkce_parameter_reuse.title = "PKCE parameter uniqueness"

    def t3090_security_features_used(self, sec_nonce_is_used, sec_pkce_is_used, **_):
        if not (sec_nonce_is_used or sec_pkce_is_used):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Neither nonce nor PKCE are used in the authorization request. "
                "Either of these mechanisms must be used to protect the authorization request from replay and CSRF attacks.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Nonce or PKCE are used to protect the authorization request from replay and CSRF attacks.",
        )

    t3090_security_features_used.title = "Security features used"

    def t3100_authorization_details_valid(self, payload, **_):
        if not "authorization_details" in payload:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "The authorization_details parameter is not used in the authorization request.",
                service_information={
                    "Payment service requested": "no",
                    "Signing service requested": "no",
                },
            )

        # try to parse authorization_details as JSON
        try:
            authorization_details_parsed = json.loads(payload["authorization_details"])
        except json.JSONDecodeError:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The authorization_details parameter is not valid JSON.",
                service_information={"authorization_details": "Invalid JSON"},
            )

        # Test against JSON schema
        success, error = validate_with_json_schema(
            authorization_details_parsed, "authorization_details.json"
        )
        if not success:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The authorization_details parameter is not valid (see below for details).",
                extra_info=error,
            )

        signing_service_used = False
        payment_service_used = False
        for obj in authorization_details_parsed:
            if obj["type"] == "sign":
                signing_service_used = True
            elif obj["type"] == "payment_initiation":
                payment_service_used = True

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The authorization_details parameter is valid.",
            service_information={
                "Payment service requested": "yes" if payment_service_used else "no",
                "Signing service requested": "yes" if signing_service_used else "no",
            },
        )

    t3100_authorization_details_valid.title = "Authorization details"

    def t3110_no_extra_parameters(self, payload, **_):
        PERMITTED_PARAMETERS = [
            "client_id",
            "redirect_uri",
            "response_type",
            "scope",
            "claims",
            "state",
            "nonce",
            "code_challenge",
            "code_challenge_method",
            "authorization_details",
        ]

        # Check that no extra parameters are present
        extra_parameters = set(payload.keys()) - set(PERMITTED_PARAMETERS)
        if len(extra_parameters) > 0:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                f"The following parameters are not defined in the yes® spec and should not be used in the authorization request: {extra_parameters}.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "No extra parameters are present in the authorization request.",
        )

    t3110_no_extra_parameters.title = "No extra parameters"


def dump_cherrypy_request_headers(request):
    return (
        f"{request.method} {request.path_info}{'?' if request.query_string != '' else ''}{request.query_string}\n"
        + "\n".join(c + ": " + v for c, v in request.headers.items())
    )


class POSTRequestTestSet(RPTestSet):
    def t0000_is_post_request(self, request, **_):

        extra_info = {"Request Headers": dump_cherrypy_request_headers(request)}
        # request is a cherrypy.request object
        if request.method != "POST":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request method is not POST. This endpoint only accepts POST requests.",
                skip_all_further_tests=True,
                extra_info=extra_info,
            )
        else:
            extra_info["Request Body"] = request.body.read()
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "The request method is POST.",
                extra_info=extra_info,
            )

    t0000_is_post_request.title = "Request method"


class PushedAuthorizationRequestTestSet(
    POSTRequestTestSet,
    AuthorizationRequestTestSet,
    ClientIDTestSet,
    ClientAuthenticationTestSet,
):
    def t0001_mime_type_is_json(self, request, **_):
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

    t0001_mime_type_is_json.title = "Content-Type header"

    def t0002_has_valid_json_body(self, request, **_):
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

    t0002_has_valid_json_body.title = "JSON Request body"


class GETRequestTestSet(RPTestSet):
    def t0000_is_get_request(self, request, **_):
        extra_info = {"Request Headers": dump_cherrypy_request_headers(request)}
        # request is a cherrypy.request object
        if request.method != "GET":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The request method is not GET, but '{request.method}'. This endpoint only accepts GET requests.",
                skip_all_further_tests=True,
                extra_info=extra_info,
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "The request method is GET.",
                extra_info=extra_info,
            )

    t0000_is_get_request.title = "Request Method"

    def t0001_request_url_assembled_correctly(self, request, **_):
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
        payload = {
            key: value[0]
            for key, value in parsed.items()
            if key != "predefined_parameter"
        }

        if not "predefined_parameter" in parsed:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The parameter 'predefined_parameter' is missing. Please take care to pass on all parameters from the authorization_endpoint configuration.",
                output_data={"payload": payload},
            )
        else:

            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "The request URL is properly formatted.",
                output_data={"payload": payload},
            )

    t0001_request_url_assembled_correctly.title = "Request URL"


class TraditionalAuthorizationRequestTestSet(
    GETRequestTestSet, ClientIDTestSet, AuthorizationRequestTestSet
):
    NAME = "RFC6749 Authorization Request"
    DESCRIPTION = "Traditional Authorization Request as defined in RFC6749."


class PARRequestURIAuthorizationRequestTestSet(GETRequestTestSet, ClientIDTestSet):
    NAME = "Authorization Request following Pushed Authorization Request"
    DESCRIPTION = "Authorization Request after PAR."

    def t0002_has_request_uri_parameter(self, payload, **_):
        if not "request_uri" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request does not contain a 'request_uri' parameter.",
            )

    def t0003_request_uri_parameter_is_valid(self, **_):
        pass
