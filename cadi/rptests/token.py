from datetime import datetime

from cadi.tools import calculate_pkce_challenge_from_verifier

from ..rptestmechanics import RPTestResult, RPTestResultStatus
from .common.client_authentication import ClientAuthenticationTestSet
from .common.client_id import ClientIDTestSet
from .common.requests import POSTRequestTestSet


class TokenRequestTestSet(
    POSTRequestTestSet,
    ClientIDTestSet,
    ClientAuthenticationTestSet,
):
    NUMBER = "2"
    NAME = "Token Request"
    DESCRIPTION = "Token Request as defined in RFC6749."

    CODE_EXPIRE_WARNING_AFTER = 30  # seconds
    CODE_EXPIRE_FAILURE_AFTER = 180  # seconds
    USED_CODES_EXPIRATION = 60 * 60 * 24

    def t3000_grant_type_parameter(self, payload, **_):
        if not "grant_type" in payload:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                "The request does not contain a `grant_type` parameter. "
                "The token request must contain a `grant_type` parameter with the value `authorization_code`."
                ,
            )

        if not payload["grant_type"] == "authorization_code":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The request contains a `grant_type` parameter with the value `{payload['grant_type']}`, but it must be set to `authorization_code`.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The request contains a `grant_type` parameter with the value `authorization_code`.",
        )

    t3000_grant_type_parameter.title = "Grant type parameter present and valid?"

    def t3010_code_parameter(self, payload, **_):
        if not "code" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request does not contain the `code` parameter.",
            )

        code = payload["code"]
        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The request contains the `code` parameter with the value `{code}`.",
            output_data={"code": code},
        )

    t3010_code_parameter.title = "Authorization code parameter present?"

    def t3011_session_exists_for_code(self, code, client_id, **_):
        session = self.session_manager.find(client_id, authorization_code=code)
        if session:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                f"A session was found for the given authorization code.",
                output_data={"session": session},
            )

        return RPTestResult(
            RPTestResultStatus.FAILURE,
            f"The request contains a `code` parameter with the value `{code}` which we do not recognize. " +
            "Please check the following things: \n\n" + 
            " 1. That the code was used exactly as provided in the authorization response. \n" +
            " 1. That the code was used immediately after it was issued. If you waited a long time before using the code, or used an old code value, the code may have expired. \n" +
            " 1. That you used the same client_id in the authorization request and in the current request. \n" +
            "\nPlease start a new authorization process to get a new code. ",
        )

    t3011_session_exists_for_code.title = "Session exists for authorization code parameter?"

    def t3012_code_has_not_expired(self, session, **_):
        # Calculate how long ago the session was created
        elapsed = int((datetime.utcnow() - session.created_at).total_seconds())

        if elapsed > self.CODE_EXPIRE_FAILURE_AFTER:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The authorization code has expired. "
                f"The code was created {elapsed} seconds ago. "
                "The authorization code should be used immediately after it was issued.",
            )

        if elapsed > self.CODE_EXPIRE_WARNING_AFTER:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                f"With a real identity provider, the authorization code may now have expired. "
                f"The code was created {elapsed} seconds ago. "
                "The authorization code should be used immediately after it was issued.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The authorization code has not expired. "
            f"The code was created {elapsed} seconds ago.",
        )

    t3012_code_has_not_expired.title = "Authorization code has not expired?"

    def t3013_code_has_not_been_used(self, session, **_):
        if session.used_code:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                "This code has been used before. This will not work with real IDPs. "
                "Authorization codes can only be used once.",
            )

        session.used_code = True
        self.session_manager.store(session)

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "This code has not been used before.",
        )

    t3013_code_has_not_been_used.title = "Authorization code has not been used before?"

    def t3020_redirect_uri_matches(self, session, payload, **_):
        if not "redirect_uri" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request does not contain a `redirect_uri` parameter.",
            )

        if not payload["redirect_uri"] == session.redirect_uri:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The request contains a `redirect_uri` parameter with the value `{payload['redirect_uri']}`, but it must be set to `{session.redirect_uri}`.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The request contains a `redirect_uri` parameter with the value `{session.redirect_uri}`.",
        )

    t3020_redirect_uri_matches.title = "Redirect URI matches one of the registered redirect URIs?"

    def t3030_pkce_code_verifier_parameter(self, session, payload, **_):
        if session.code_challenge is not None:
            if not "code_verifier" in payload:
                return RPTestResult(
                    RPTestResultStatus.FAILURE,
                    "The request does not contain a `code_verifier` parameter. If you use a `code_challenge` parameter in the authorization request, "
                    "you must also provide a `code_verifier` parameter in the token request.",
                )
            else:
                code_verifier = payload["code_verifier"]
                expected_challenge = calculate_pkce_challenge_from_verifier(code_verifier)

                if session.code_challenge != expected_challenge:
                    return RPTestResult(
                        RPTestResultStatus.FAILURE,
                        f"The request contains a `code_verifier` parameter with the value `{code_verifier}`, that does not match the `code_challenge` parameter that was used in the authorization request. "
                        f"For the provided `code_verifier={code_verifier}`, the `code_challenge` would be `{expected_challenge}`, but not `{session.code_challenge}`, which was contained "
                        "in your authorization request. "
                        "Please check that you are computing the `code_challenge` correctly (refer to the reference below).",
                    )
                else:
                    return RPTestResult(
                        RPTestResultStatus.SUCCESS,
                        "The provided `code_verifier` matches the `code_challenge` parameter that was used in the authorization request.",
                    )
        else:
            if "code_verifier" in payload:
                return RPTestResult(
                    RPTestResultStatus.FAILURE,
                    "The request contains a `code_verifier` parameter, but the `code_challenge` parameter was not provided in the authorization request. "
                    "You should not send a `code_verifier` parameter in the token request without a `code_challenge` parameter in the authorization response.",
                )
            else:
                return RPTestResult(
                    RPTestResultStatus.SKIPPED,
                    "The request does not contain a `code_verifier` parameter. Since no `code_challenge` parameter was provided in the authorization request, "
                    "the `code_verifier` parameter is not required in the token request.",
                )

    t3030_pkce_code_verifier_parameter.title = "PKCE code verifier parameter present and valid?"
    t3030_pkce_code_verifier_parameter.references = [
        (
            "RFC7636 - Proof Key for Code Exchange",
            "https://datatracker.ietf.org/doc/html/rfc7636",
        ),
    ]