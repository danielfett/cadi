from datetime import datetime
import json
from ..rptestmechanics import RPTestResult, RPTestResultStatus

from .common.requests import POSTRequestTestSet, GETRequestTestSet
from .common.authorization_request import AuthorizationRequestTestSet
from .common.client_id import ClientIDTestSet
from .common.client_authentication import ClientAuthenticationTestSet


class TokenRequestTestSet(
    POSTRequestTestSet,
    ClientIDTestSet,
    ClientAuthenticationTestSet,
):
    NAME = "Token Request (RFC6749)"
    DESCRIPTION = "Token Request as defined in RFC6749."

    CODE_EXPIRE_WARNING_AFTER = 30  # seconds
    CODE_EXPIRE_FAILURE_AFTER = 180 # seconds

    def t3000_grant_type_parameter(self, payload, **_):
        if not "grant_type" in payload:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                "The request does not contain a 'grant_type' parameter.",
            )

        if not payload['grant_type'] == 'authorization_code':
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

        code = payload['code']
        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The request contains a 'code' parameter with the value '{code}'.",
            output_data={'code': code},
        )

    t3010_code_parameter.title = "Code parameter"

    def t3011_code_parameter_can_be_found_in_session(self, code, client_sessions, **_):
        for session in client_sessions:
            if session.authorization_code == code:
                return RPTestResult(
                    RPTestResultStatus.SUCCESS,
                    f"The request contains a 'code' parameter with the value '{code}', for which there exists a session.",
                    output_data={'session': session},
                )
        
        return RPTestResult(
            RPTestResultStatus.FAILURE,
            f"The request contains a 'code' parameter with the value '{code}', for which there is no session.",
        )

    t3011_code_parameter_can_be_found_in_session.title = "Session exists for code parameter"

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

    def t3020_redirect_uri_matches(self, session, payload, **_):
        if not "redirect_uri" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request does not contain a 'redirect_uri' parameter.",
            )

        if not payload['redirect_uri'] == session.redirect_uri:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The request contains a 'redirect_uri' parameter with the value '{payload['redirect_uri']}', but it must be set to '{session.redirect_uri}'.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The request contains a 'redirect_uri' parameter with the value '{session.redirect_uri}'.",
        )
