import json
import re

from ...idp.session import IDPSession
from ...rptestmechanics import RPTestResult, RPTestResultStatus, RPTestSet
from . import validate_with_json_schema


class AuthorizationRequestTestSet(RPTestSet):
    NONCE_MIN_LENGTH = 20
    NONCE_RECOMMENDED_MIN_LENGTH = 32
    SEC_PARAMS_CACHE_EXPIRATION = 5 * 60

    PKCE_CODE_CHALLENGE_REGEX = re.compile(r"^[a-zA-Z0-9\-_]+$")
    PKCE_CODE_CHALLENGE_MIN_LENGTH = 43
    PKCE_CODE_CHALLENGE_MAX_LENGTH = 128

    PURPOSE_MIN_LENGTH = 3
    PURPOSE_MAX_LENGTH = 300
    # purpose must not contain the characters <>(){}'\
    PURPOSE_REGEX = re.compile(r"^[^<>(){}'\\]+$")

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
        "acr_values",
        "purpose",
    }

    def t3010_redirect_uri_valid(self, payload, client_config, **_):
        if not "redirect_uri" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Redirect URI (`redirect_uri`) parameter is missing in the authorization request.",
            )

        # Check that the redirect URI exactly matches the one in the client configuration
        if payload["redirect_uri"] not in client_config["redirect_uris"]:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Redirect URI (`redirect_uri`) in the authorization request does not match one from the client configuration. "
                "If you need a different redirect URI registered, please contact yes®. "
                "Note that for security reasons, the redirect URI must match exactly a registered redirect URI.\n\n",
                "Redirect URI (`redirect_uri`) in the authorization request: `{payload['redirect_uri']}`  \n\n"
                "Redirect URIs in the client configuration: "
                + self._list_parameters(client_config["redirect_uris"]),
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Redirect URI (`redirect_uri`) parameter is present in the authorization request and the provided redirect URI matches one of the registered redirect URIs in the client configuration.",
            output_data={"redirect_uri": payload["redirect_uri"]},
        )

    t3010_redirect_uri_valid.title = "Redirect URI parameter present and valid?"
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
                "Claims parameter (`claims`) is not used in the authorization request. This means that the identity service is not used.",
                output_data={"claims_parameter_provided": False},
            )

        # Check that the claims are valid according to the specification
        try:
            claims = json.loads(payload["claims"])
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "The `claims` parameter is present in the authorization request and is a valid JSON object.",
                output_data={
                    "claims_parameter_provided": True,
                    "claims_parsed": claims,
                },
                request_info={
                    "Claims Parameter": self._code(json.dumps(claims, indent=4)),
                },
            )
        except Exception as e:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Claims (`claims`) in the authorization request is not valid JSON syntax. Please see below for details.",
                extra_details=self._code(str(e)),
            )

    t3020_claims_valid.title = "Claims parameter present and syntactically valid?"
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
        if not isinstance(claims_parsed, dict):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Claims (`claims`) in the authorization request must be a JSON **object**, not a list or something else.",
            )

        # Only userinfo and id_token must be top-level elements in the claims parameter
        if not set(claims_parsed.keys()) <= {"userinfo", "id_token"}:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The claims parameter must only contain the top-level elements `userinfo` and `id_token`.",
            )

        # Test against JSON schema
        success, error = validate_with_json_schema(claims_parsed, "ekyc.json")
        if not success:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The JSON structure in the `claims` parameter is not valid (see below for details).",
                extra_details=self._code(str(error)),
            )

        problems = []

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
                problems.extend(
                    f"unverified claim '{claim}' in {endpoint} endpoint: {p}"
                    for p in self._check_claim_request_value(
                        claims_parsed[endpoint][claim]
                    )
                )
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
                problems.extend(
                    f"verified claim '{claim}' in {endpoint} endpoint: {p}"
                    for p in self._check_claim_request_value(
                        verified_claims["claims"][claim]
                    )
                )
                verified_claims_requested.append(claim)

        unverified_claims_requested = set(unverified_claims_requested)
        verified_claims_requested = set(verified_claims_requested)

        if not len(problems):
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "The claims parameter is valid according to the specification.",
                output_data={
                    "unverified_claims_requested": unverified_claims_requested,
                    "verified_claims_requested": verified_claims_requested,
                },
                service_information={
                    "Claims (verified) requested": ", ".join(verified_claims_requested),
                    "Claims (unverified) requested": ", ".join(
                        unverified_claims_requested
                    ),
                },
            )
        else:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                "There are problems with one or more claims:" + self._list(problems),
                output_data={
                    "unverified_claims_requested": unverified_claims_requested,
                    "verified_claims_requested": verified_claims_requested,
                },
                service_information={
                    "Claims (verified) requested": ", ".join(verified_claims_requested),
                    "Claims (unverified) requested": ", ".join(
                        unverified_claims_requested
                    ),
                },
            )

    t3021_claims_valid.title = "Claims parameter contents valid?"

    def _check_claim_request_value(self, claim_request):
        if claim_request is None:
            return

        if not isinstance(claim_request, dict):
            yield "Claim must either be 'null' or a JSON object"

        if list(claim_request.keys()) != ["essential"]:
            yield (
                "Claim should be 'null' or a JSON object with the key 'essential'. "
                "Other keys should not be used."
            )

        if not isinstance(claim_request["essential"], bool):
            yield "The value of 'essential' must be a boolean."

        return

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
                + self._list_parameters(
                    not_allowed_unverified_claims | not_allowed_verified_claims
                )
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

    t3022_claims_within_allowed_claims.title = (
        "Claims permitted according to configuration?"
    )

    def t3023_has_verified_claims(self, verified_claims_requested, **_):
        # Check that at least one verified claim has been requested
        if not len(verified_claims_requested):
            return RPTestResult(
                RPTestResultStatus.WARNING,
                "No verified claims have been requested. Unverified claims can be modified by the customer. "
                "Depending on your use case, you might want to request verified claims."
                "Please consult the developer documentation for more information."
                , 
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "At least one verified claim has been requested.",
        )

    t3023_has_verified_claims.title = "Verified claims requested?"
    t3023_has_verified_claims.references = [
        (
            "yes® Relying Party Developer Guide, Identity Service, Section 1",
            "https://yes.com/docs/rp-devguide/latest/IDENTITY/index.html#_verified_and_unverified_data"
        )
    ]

    def t3030_scope_format(self, payload, **_):
        # Scope is optional, but only for non-identity flows
        if not "scope" in payload:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "Scope parameter (`scope`) is not used in the authorization request. This means that the identity service is not requested.",
                output_data={"scopes_list": []},
            )

        # The scope parameter must be a space-separated list of strings
        REGEX = r"^\w+( \w+)*$"
        if not re.match(REGEX, payload["scope"]):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Scope parameter (`scope`) is not a space-separated list of strings.",
            )

        # The scope parameter must contain 'openid' if the claims parameter is used
        scopes_list = payload["scope"].split(" ")
        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Scope parameter (`scope`) is provided and of the correct format.",
            output_data={"scopes_list": scopes_list},
        )

    t3030_scope_format.title = "Scope parameter present and syntactically valid?"
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
                "Scope parameter (`scope`) must contain `openid` in identity flows. "
                "Your use of the 'claims' parameter indicates that you want to use the identity flow. "
                "In this case, using `scope=openid` is mandatory.",
                output_data={"scopes_list": scopes_list},
            )

        # If 'openid' scope is used, the claims parameter should be used as well
        if "openid" in scopes_list and not claims_parameter_provided:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                "You are using the identity service (scope contains `openid`), but you are not using the `claims` parameter. "
                "The `claims` parameter should be used to select the claims that are returned in the ID token and on the userinfo response.",
                output_data={"scopes_list": scopes_list},
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Scope parameter (`scope`) use matches the use case.",
            service_information={
                "Service Identity requested": "yes"
                if ("openid" in scopes_list)
                else "no",
            },
        )

    t3031_scope_matches_service_usage.title = "Scope parameter matches use case?"
    t3031_scope_matches_service_usage.references = [
        (
            "yes® Relying Party Developer Guide, Identity Service, Section 3.2.1",
            "https://yes.com/docs/rp-devguide/latest/IDENTITY/index.html#_parameters",
        ),
    ]

    def t3032_scope_allowed_values(self, scopes_list, **_):
        # Some scopes are known, but should not be used
        SHOULD_NOT_USE = {"profile", "email", "address", "phone", "offline_access"}
        scopes_set = set(scopes_list)

        used_but_should_not = SHOULD_NOT_USE.intersection(scopes_set)

        if len(used_but_should_not):
            return RPTestResult(
                RPTestResultStatus.WARNING,
                f"Scope parameter (`scope`) contains one or more values which should not be used: "
                + self._list_parameters(used_but_should_not)
                + "While defined by the OpenID Connect specification, the parameter is not suitable to request "
                "verified claims.",
            )

        # Other scopes should not be used at all
        unknown_scopes = scopes_set - {"openid"} - SHOULD_NOT_USE

        if len(unknown_scopes):
            return RPTestResult(
                RPTestResultStatus.WARNING,
                f"Scope parameter (`scope`) contains one or more unknown scopes:"
                + self._list_parameters(unknown_scopes),
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Scope parameter (`scope`) looks fine.",
        )

    t3032_scope_allowed_values.title = "Only recommended scopes used?"

    def t3040_response_type_valid(self, payload, **_):
        if not "response_type" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Response type parameter (`response_type`) must be present in the authorization request. Set `response_type=code` for yes® flows.",
            )

        if payload["response_type"] != "code":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Response type parameter (`response_type`) must be set to `code`, but it is `{payload['response_type']}`. Set `response_type=code` for yes® flows.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Response type parameter (`response_type`) is set to `code`.",
            output_data={"response_type": payload["response_type"]},
        )

    t3040_response_type_valid.title = "Response type present and valid?"
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
                "`acr_values` parameter is not used in the authorization request. Since it is not required, this is fine. "
                "This means that no particular authentication method (one factor or two factors) is requested from the user.",
                service_information={"Second-factor authentication": "Not requested"},
            )

        # The acr_values parameter must be a space-separated list of strings
        REGEX = r"^\S+( \S+)*$"
        if not re.match(REGEX, payload["acr_values"]):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"`acr_values` parameter must be a space-separated list of strings. Current value: `{payload['acr_values']}`",
            )

        # The acr_values parameter must contain 'openid' if the claims parameter is used
        acr_values_list = payload["acr_values"].split(" ")

        ACR_DEF = "https://www.yes.com/acrs/online_banking"
        ACR_2FA = "https://www.yes.com/acrs/online_banking_sca"

        for val in acr_values_list:
            if val not in [ACR_DEF, ACR_2FA]:
                return RPTestResult(
                    RPTestResultStatus.FAILURE,
                    f"`acr_values` parameter contains unknown value '{val}'. "
                    f"Only `{ACR_DEF}` and `{ACR_2FA}` are allowed.",
                )

        if len(acr_values_list) > 1:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                "`acr_values` parameter contains more than one value. "
                f"It is recommended to use only one of the allowed values (`{ACR_DEF}` or `{ACR_2FA}`).",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "`acr_values` parameter is present in the authorization request, is of the correct format and contains a valid value.",
            service_information={
                "Second-factor authentication": "Requested"
                if ACR_2FA in acr_values_list
                else "Not requested"
            },
        )

    t3050_acr_values_valid.title = "ACR values parameter present and valid?"
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
                "State parameter is not used in the authorization request. "
                "This is fine. The state parameter is optional, and may be used to prevent CSRF attacks.",
                service_information={"Security: State parameter": "Not used"},
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "State parameter is used in the authorization request.",
                service_information={"Security: State parameter": "In use"},
                output_data={"state": payload["state"]},
            )

    t3060_state_value_used.title = "State parameter present?"

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
                f"Nonce parameter (`nonce`) is too short. It must be at least **{self.NONCE_MIN_LENGTH} characters** long, **{self.NONCE_RECOMMENDED_MIN_LENGTH} characters** are recommended."
                f"\n\nNonce value: `{nonce}`",
                service_information={"Security: Nonce parameter": "In use"},
                output_data={"nonce": nonce, "sec_nonce_is_used": True},
            )

        if len(nonce) < self.NONCE_RECOMMENDED_MIN_LENGTH:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                f"Nonce parameter (`nonce`) is only {len(nonce)} characters long. It is recommended to use at least **{self.NONCE_RECOMMENDED_MIN_LENGTH} random characters.**"
                f"\n\nNonce value: `{nonce}`",
                service_information={"Security: Nonce parameter": "In use"},
                output_data={"nonce": nonce, "sec_nonce_is_used": True},
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Nonce parameter is present in the authorization request and is long enough.",
            service_information={"Security: Nonce parameter": "In use"},
            output_data={"nonce": nonce, "sec_nonce_is_used": True},
        )

    t3070_nonce_value_valid.title = "Nonce parameter present and long enough?"

    def t3071_nonce_not_reused(self, client_id, nonce, **_):
        key = ("nonce-list", client_id)
        # check whether nonce matches any of the previously stored values from cache
        previous_nonces = self.cache.get(key, default=[])
        if len(previous_nonces) == 0:
            self.cache.set(key, [nonce], expire=self.SEC_PARAMS_CACHE_EXPIRATION)
            return RPTestResult(
                RPTestResultStatus.WAITING,
                "A new value for the `nonce` parameter must be used with each authorization request. "
                "To check that, you need to send at least one more authorization request. "
                f"Repeat the authorization request within {self.SEC_PARAMS_CACHE_EXPIRATION} seconds to perform this check.",
            )

        if nonce in previous_nonces:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Repeated use of the same `nonce` parameter value: `{nonce}`. "
                "This is a security risk! The `nonce` value must be chosen randomly for each new request. "
                "Previously used nonces:" + self._list_parameters(previous_nonces),
            )

        previous_nonces.append(nonce)
        self.cache.set(key, previous_nonces, expire=self.SEC_PARAMS_CACHE_EXPIRATION)
        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"Nonce parameter value is unique within the last {len(previous_nonces)} requests. "
            "Previously used nonces:" + self._list_parameters(previous_nonces),
        )

    t3071_nonce_not_reused.title = "Nonce parameter unique?"

    def t3080_pkce_use(self, payload, **_):
        if not "code_challenge" in payload and not "code_challenge_method" in payload:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "PKCE (i.e., the parameters `code_challenge` and `code_challenge_method`) is not used in the authorization request.",
                service_information={"Security: PKCE": "Not used"},
                output_data={"sec_pkce_is_used": False},
            )

        if "code_challenge" in payload and "code_challenge_method" in payload:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "PKCE (`code_challenge` and `code_challenge_method`) is used in the authorization request.",
                service_information={"Security: PKCE": "In use"},
                output_data={
                    "sec_pkce_is_used": True,
                    "code_challenge": payload["code_challenge"],
                    "code_challenge_method": payload["code_challenge_method"],
                },
            )

        return RPTestResult(
            RPTestResultStatus.FAILURE,
            "The PKCE parameters `code_challenge` and `code_challenge_method` must either both be used, or both be omitted.",
            service_information={"Security: PKCE": "Unclear"},
            output_data={"sec_pkce_is_used": False},
        )

    t3080_pkce_use.title = "PKCE in use?"
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
                f"The `code_challenge_method` parameter is set to `{code_challenge_method}`. "
                "The method `S256` must be used instead.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The `code_challenge_method` parameter is set to `S256`.",
        )

    t3081_pkce_method_valid.title = "PKCE method is S256?"
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
                f"The `code_challenge` parameter is too short. It must be at least **{self.PKCE_CODE_CHALLENGE_MIN_LENGTH} characters** long.",
            )
        elif len(code_challenge) > self.PKCE_CODE_CHALLENGE_MAX_LENGTH:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The `code_challenge` parameter is too long. It must not be more than **{self.PKCE_CODE_CHALLENGE_MAX_LENGTH} characters** long.",
            )

        # Check that code_challenge matches the regex
        if not self.PKCE_CODE_CHALLENGE_REGEX.match(code_challenge):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The `code_challenge` parameter contains invalid characters. It must be the base64url-encoded hash of the `code_verifier`, "
                "with any trailing `=` characters removed. "
                "Valid `code_challenge` parameters therefore only contain the following characters: `a-z` `A-Z` `0-9` `-` `_` ",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The `code_challenge` parameter looks good.",
        )

    t3082_pkce_parameters_valid.title = "PKCE Code Challenge formatted properly?"
    t3082_pkce_parameters_valid.references = [
        (
            "RFC7636 - Proof Key for Code Exchange, Section 4",
            "https://datatracker.ietf.org/doc/html/rfc7636#section-4",
        ),
    ]

    def t3083_pkce_parameter_reuse(self, client_id, code_challenge, **_):
        key = ("pkce-list", client_id)
        # check whether code_challenge matches any of the previously stored values from cache
        previous_code_challenges = self.cache.get(key, default=[])
        if len(previous_code_challenges) == 0:
            self.cache.set(
                key, [code_challenge], expire=self.SEC_PARAMS_CACHE_EXPIRATION
            )
            return RPTestResult(
                RPTestResultStatus.WAITING,
                "A new value for the `code_challenge` parameter must be used with each authorization request. "
                "To check that, you need to send at least one more authorization request. "
                f"Repeat the authorization request within {self.SEC_PARAMS_CACHE_EXPIRATION} seconds to perform this check.",
            )

        if code_challenge in previous_code_challenges:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "A new value for the `code_challenge` parameter must be used with each authorization request. "
                f"Within the last requests, we saw the following `code_challenge` parameter more than once: `{code_challenge}`. "
                "This is a security risk! The `code_challenge` value must be chosen randomly for each new request. "
                "Previously used code_challenges:"
                + self._list_parameters(previous_code_challenges),
            )

        previous_code_challenges.append(code_challenge)
        self.cache.set(
            key, previous_code_challenges, expire=self.SEC_PARAMS_CACHE_EXPIRATION
        )
        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The `code_challenge` parameter value is unique within the last {len(previous_code_challenges)} requests. "
            "Previously used code_challenges:"
            + self._list_parameters(previous_code_challenges),
        )

    t3083_pkce_parameter_reuse.title = "PKCE parameter unique?"

    def t3090_security_features_used(self, sec_nonce_is_used, sec_pkce_is_used, **_):
        if not (sec_nonce_is_used or sec_pkce_is_used):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Neither Nonce nor PKCE are used in the authorization request. "
                "Either of these mechanisms must be used to protect the authorization request from replay and CSRF attacks.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Nonce or PKCE are used to protect the authorization request from replay and CSRF attacks.",
        )

    t3090_security_features_used.title = "Protected against replay and CSRF attacks?"

    def t3100_authorization_details_valid(self, payload, **_):
        if not "authorization_details" in payload:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "The `authorization_details` parameter is not used in the authorization request. "
                "This is fine - it means that the the signing nor payment initiation services are not used.",
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
                "The `authorization_details` parameter is not valid JSON.",
                service_information={"authorization_details": "Invalid JSON"},
            )

        # Test against JSON schema
        success, error = validate_with_json_schema(
            authorization_details_parsed, "authorization_details.json"
        )
        if not success:
            # TODO: The output of this seems to be broken. Some markdown-parser problem.
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The `authorization_details` parameter is not valid. Error: \n\n"
                + self._code(error),
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
            "The `authorization_details` parameter is valid.",
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

    t3100_authorization_details_valid.title = (
        "Authorization details parameter present and syntactically valid?"
    )
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

    def t3101_authorization_details_types_allowed(self, client_config, authorization_details_parsed, **_):
        authorization_details_types_used = set(element['type'] for element in authorization_details_parsed)
        authorization_details_types_allowed = set(client_config['allowed_authorization_data_types'])

        not_allowed_authorization_details_types = authorization_details_types_used - authorization_details_types_allowed
        if len(not_allowed_authorization_details_types):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "You used services that were not configured for this client ID: "
                + self._list_parameters(not_allowed_authorization_details_types)
                + "Please contact yes® to fix this."
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "All services permitted according to configuration."
        )

    t3101_authorization_details_types_allowed.title = "Services allowed in configuration?"
    # TODO: Check the length of the document hashes

    def t3110_purpose_length(self, payload, **_):
        if not "purpose" in payload:
            return RPTestResult(
                RPTestResultStatus.INFO,
                "The `purpose` parameter is not used in the authorization request. "
                "This is fine - it means that the registered default purpose is used.",
                service_information={"purpose": "default"},
            )

        purpose = payload["purpose"]
        if len(purpose) > self.PURPOSE_MAX_LENGTH:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The `purpose` parameter is too long. "
                f"It must be no longer than {self.PURPOSE_MAX_LENGTH} characters.",
                service_information={"purpose": purpose},
            )

        if len(purpose) < self.PURPOSE_MIN_LENGTH:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The `purpose` parameter is too short. "
                f"It must be at least {self.PURPOSE_MIN_LENGTH} characters.",
                service_information={"purpose": purpose},
            )

        # check that purpose matches regular expression
        if not re.match(self.PURPOSE_REGEX, purpose):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The `purpose` parameter is not valid. "
                f"It must match the following regular expression: {self.PURPOSE_REGEX}",
                service_information={"purpose": purpose},
            )
            # TODO: Better explanation for users

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The `purpose` parameter is valid.",
            service_information={"purpose": purpose},
        )

    t3110_purpose_length.title = "Purpose parameter length ok?"

    def t3120_no_extra_parameters(self, payload, **_):

        # Check that no extra parameters are present
        extra_parameters = set(payload.keys()) - self.PERMITTED_PARAMETERS
        if len(extra_parameters) > 0:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                "The following parameters are not defined in the yes® spec and should not be used in the authorization request: "
                + self._list_parameters(extra_parameters)
                + "If you added this or these parameters on purpose, please check that they are spelled correctly!",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "No extra parameters are present in the authorization request.",
        )

    t3120_no_extra_parameters.title = "No extra parameters present?"

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
        **_,
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

        self.session_manager.store(session)

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "Authorization Endpoint was called successfully.",
            output_data={"session": session},
        )

    t3120_create_session.title = "Authorization request complete?"
