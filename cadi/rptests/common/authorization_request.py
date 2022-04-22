import json
import re
from ...rptestmechanics import RPTestSet, RPTestResult, RPTestResultStatus
from . import validate_with_json_schema

from ...idp.session import IDPSession


class AuthorizationRequestTestSet(RPTestSet):
    NONCE_MIN_LENGTH = 20
    NONCE_RECOMMENDED_MIN_LENGTH = 32
    SEC_PARAMS_CACHE_EXPIRATION = 5 * 60

    PKCE_CODE_CHALLENGE_REGEX = re.compile(r"^[a-zA-Z0-9\-._~]{43,128}$")
    PKCE_CODE_CHALLENGE_MIN_LENGTH = 43

    PERMITTED_PARAMETERS = {
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
    }

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
                extra_details=f"Redirect URI (redirect_uri) in the authorization request: {payload['redirect_uri']}\n"
                f"Redirect URIs in the client configuration: {', '.join(client_config['redirect_uris'])}",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Redirect URI (redirect_uri) parameter is present in the authorization request and the provided redirect URI matches one of the registered redirect URIs in the client configuration.",
            output_data={"redirect_uri": payload["redirect_uri"]},
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
                    request_info={
                        "Claims Parameter": json.dumps(claims, indent=4),
                    },
                )
        except Exception as e:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Claims (claims) in the authorization request is not a valid JSON object.",
                extra_details=str(e),
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
                extra_details=error,
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

        unverified_claims_requested = set(unverified_claims_requested)
        verified_claims_requested = set(verified_claims_requested)

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The claims parameter is valid according to the specification.",
            output_data={
                "unverified_claims_requested": unverified_claims_requested,
                "verified_claims_requested": verified_claims_requested,
            },
            service_information={
                "Claims (verified) requested": ", ".join(verified_claims_requested),
                "Claims (unverified) requested": ", ".join(unverified_claims_requested),
            },
        )

    t3021_claims_valid.title = "Claims parameter format"

    def t3022_claims_within_allowed_claims(
        self, client_config, unverified_claims_requested, verified_claims_requested, **_
    ):
        # All unverified claims must be listed in the allowed_claims
        not_allowed_unverified_claims = unverified_claims_requested - set(
            client_config["allowed_claims"]
        )
        not_allowed_verified_claims = verified_claims_requested - set(
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
        (
            "RFC6749 - OAuth 2.0, Appendix A.4",
            "https://tools.ietf.org/html/rfc6749#appendix-A.4",
        ),
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
                "Service Identity requested": "yes"
                if ("openid" in scopes_list)
                else "no",
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
            output_data={"response_type": payload["response_type"]},
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
                service_information={"Security: State parameter": "Not used"},
            )
        else:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "State parameter is used in the authorization request.",
                service_information={"Security: State parameter": "In use"},
                output_data={"state": payload["state"]},
            )

    t3060_state_value_used.title = "State parameter use"

    def t3070_nonce_value_valid(self, payload, **_):
        if not "nonce" in payload:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "Nonce parameter is not used in the authorization request.",
                service_information={"Security: Nonce parameter": "Not used"},
                output_data={"sec_nonce_is_used": False},
            )

        nonce = payload["nonce"]
        if len(nonce) < self.NONCE_MIN_LENGTH:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Nonce parameter (nonce) is too short. It must be at least {self.NONCE_MIN_LENGTH} characters long.",
                service_information={"Security: Nonce parameter": "In use"},
                output_data={"nonce": nonce, "sec_nonce_is_used": True},
            )

        if len(nonce) < self.NONCE_RECOMMENDED_MIN_LENGTH:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                f"Nonce parameter (nonce) is only {len(nonce)} characters long. It is recommended to use at least {self.NONCE_RECOMMENDED_MIN_LENGTH} characters long.",
                service_information={"Security: Nonce parameter": "In use"},
                output_data={"nonce": nonce, "sec_nonce_is_used": True},
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Nonce parameter is present in the authorization request, and is long enough.",
            service_information={"Security: Nonce parameter": "In use"},
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
                extra_details="Previously used nonces:\n" + "\n".join(previous_nonces),
            )

        previous_nonces.append(nonce)
        self.cache.set(key, previous_nonces, expire=self.SEC_PARAMS_CACHE_EXPIRATION)
        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"Nonce parameter value is unique within the last {len(previous_nonces)} requests. ",
            extra_details="Previously used nonces:\n" + "\n".join(previous_nonces),
        )

    t3071_nonce_not_reused.title = "Nonce parameter uniqueness"

    def t3080_pkce_use(self, payload, **_):
        if not "code_challenge" in payload and not "code_challenge_method" in payload:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "PKCE (code_challenge and code_challenge_method) is not used in the authorization request.",
                service_information={"Security: PKCE": "Not used"},
                output_data={"sec_pkce_is_used": False},
            )

        if "code_challenge" in payload and "code_challenge_method" in payload:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "PKCE (code_challenge and code_challenge_method) is used in the authorization request.",
                service_information={"Security: PKCE": "In use"},
                output_data={
                    "sec_pkce_is_used": True,
                    "code_challenge": payload["code_challenge"],
                    "code_challenge_method": payload["code_challenge_method"],
                },
            )

        return RPTestResult(
            RPTestResultStatus.FAILURE,
            "The PKCE parameters code_challenge and code_challenge_method must either both be used, or both be omitted.",
            service_information={"Security: PKCE": "Unclear"},
            output_data={"sec_pkce_is_used": False},
        )

    t3080_pkce_use.title = "PKCE use"
    t3080_pkce_use.references = [
        (
            "RFC7636 - Proof Key for Code Exchange, Section 4",
            "https://datatracker.ietf.org/doc/html/rfc7636#section-4",
        ),
    ]

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
    t3081_pkce_method_valid.references = [
        (
            "RFC7636 - Proof Key for Code Exchange, Section 4",
            "https://datatracker.ietf.org/doc/html/rfc7636#section-4",
        ),
    ]

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
    t3082_pkce_parameters_valid.references = [
        (
            "RFC7636 - Proof Key for Code Exchange, Section 4",
            "https://datatracker.ietf.org/doc/html/rfc7636#section-4",
        ),
    ]

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
                extra_details="Previously used code_challenges:\n"
                + "\n".join(previous_code_challenges),
            )

        previous_code_challenges.append(code_challenge)
        self.cache.set(
            key, previous_code_challenges, expire=self.SEC_PARAMS_CACHE_EXPIRATION
        )
        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The code_challenge parameter value is unique within the last {len(previous_code_challenges)} requests. ",
            extra_details="Previously used code_challenges:\n"
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
                    "Service Payment Initiation requested": "no",
                    "Service Signing requested": "no",
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
                extra_details=error,
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
                "Service Payment Initiation requested": "yes"
                if payment_service_used
                else "no",
                "Service Signing requested": "yes" if signing_service_used else "no",
            },
            output_data={
                "authorization_details_parsed": authorization_details_parsed,
            },
        )

    t3100_authorization_details_valid.title = "Authorization details"
    t3100_authorization_details_valid.references = [
        (
            "yes® Relying Party Developer Guide, Signing Service, Section 3.2.1",
            "https://yes.com/docs/rp-devguide/latest/QES/index.html#_authorization_details",
        ),
        (
            "yes® Relying Party Developer Guide, Payment Initiation Service, Section 2.2.1",
            "https://yes.com/docs/rp-devguide/latest/PIS/index.html#_authorization_details",
        ),
        (
            "draft-ietf-oauth-rar - OAuth 2.0 Rich Authorization Requests",
            "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar",
        ),
    ]

    def t3110_no_extra_parameters(self, payload, **_):

        # Check that no extra parameters are present
        extra_parameters = set(payload.keys()) - self.PERMITTED_PARAMETERS
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

    def t3120_create_session(
        self,
        client_id,
        redirect_uri,
        response_type,
        scopes_list=None,
        claims_parsed=None,
        state=None,
        nonce=None,
        code_challenge=None,
        code_challenge_method=None,
        authorization_details_parsed=None,
        **_
    ):
        # Create IDPSession
        session = IDPSession(
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scopes_list=scopes_list,
            claims=claims_parsed,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            authorization_details=authorization_details_parsed,
        )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Authorization Endpoint was called successfully.",
            output_data={"session": session},
        )

    t3120_create_session.title = "Create session"
