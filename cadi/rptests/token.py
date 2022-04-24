from datetime import datetime

from ..rptestmechanics import RPTestResult, RPTestResultStatus
from .common.client_authentication import ClientAuthenticationTestSet
from .common.client_id import ClientIDTestSet
from .common.requests import POSTRequestTestSet


class TokenRequestTestSet(
    POSTRequestTestSet,
    ClientIDTestSet,
    ClientAuthenticationTestSet,
):
    NAME = "Token Request (RFC6749)"
    DESCRIPTION = "Token Request as defined in RFC6749."

    CODE_EXPIRE_WARNING_AFTER = 30  # seconds
    CODE_EXPIRE_FAILURE_AFTER = 180  # seconds
    USED_CODES_EXPIRATION = 60 * 60 * 24

    def t3000_grant_type_parameter(self, payload, **_):
        if not "grant_type" in payload:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                "The request does not contain a 'grant_type' parameter.",
            )

        if not payload["grant_type"] == "authorization_code":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The request contains a 'grant_type' parameter with the value '{payload['grant_type']}', but it must be set to 'authorization_code'.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The request contains a 'grant_type' parameter with the value 'authorization_code'.",
        )

    t3000_grant_type_parameter.title = "Grant type parameter"

    def t3010_code_parameter(self, payload, **_):
        if not "code" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request does not contain a 'code' parameter.",
            )

        code = payload["code"]
        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The request contains a 'code' parameter with the value '{code}'.",
            output_data={"code": code},
        )

    t3010_code_parameter.title = "Code parameter"

    def t3011_session_exists_for_code(self, code, client_id, **_):
        session = self.session_manager.find(client_id, authorization_code=code)
        if session:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                f"The request contains a 'code' parameter with the value '{code}', for which there exists a session.",
                output_data={"session": session},
            )

        return RPTestResult(
            RPTestResultStatus.FAILURE,
            f"The request contains a 'code' parameter with the value '{code}' which we do not recognize. "
            "Please check the following things: "
            "(1) That the code was used exactly as provided in the authorization response. "
            "(2) That the code was used immediately after it was issued. If you waited a long time before using the code, or used an old code value, the code may have expired. "
            "(3) That you used the same client_id in the authorization request and in the current request. "
            "Please start a new authorization process to get a new code. ",
        )

    t3011_session_exists_for_code.title = "Session exists for code parameter"

    def t3012_code_has_not_expired(self, session, **_):
        # Calculate how long ago the session was created
        elapsed = (datetime.utcnow() - session.created_at).total_seconds()

        if elapsed > self.CODE_EXPIRE_FAILURE_AFTER:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The authorization code has expired. "
                f"The session was created {elapsed} seconds ago. "
                "The authorization code should be used immediately after it was issued.",
            )

        if elapsed > self.CODE_EXPIRE_WARNING_AFTER:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                f"The authorization code may have expired in practice. "
                f"The session was created {elapsed} seconds ago. "
                "The authorization code should be used immediately after it was issued.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The authorization code has not expired. "
            f"The session was created {elapsed} seconds ago.",
        )

    t3012_code_has_not_expired.title = "Code has not expired"

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

    t3013_code_has_not_been_used.title = "Code has not been used before"

    def t3020_redirect_uri_matches(self, session, payload, **_):
        if not "redirect_uri" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request does not contain a 'redirect_uri' parameter.",
            )

        if not payload["redirect_uri"] == session.redirect_uri:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The request contains a 'redirect_uri' parameter with the value '{payload['redirect_uri']}', but it must be set to '{session.redirect_uri}'.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The request contains a 'redirect_uri' parameter with the value '{session.redirect_uri}'.",
        )

    t3020_redirect_uri_matches.title = "Redirect URI matches"
