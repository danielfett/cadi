from datetime import datetime

from ..rptestmechanics import RPTestResult, RPTestResultStatus
from .common.authorization_request import AuthorizationRequestTestSet
from .common.client_authentication import ClientAuthenticationTestSet
from .common.client_id import ClientIDTestSet
from .common.requests import GETRequestTestSet, POSTRequestTestSet


class PushedAuthorizationRequestTestSet(
    POSTRequestTestSet,
    AuthorizationRequestTestSet,
    ClientIDTestSet,
    ClientAuthenticationTestSet,
):
    NUMBER = "1a"
    NAME = "Pushed Authorization Request"
    DESCRIPTION = "Backend Pushed Authorization Request as defined in RFC9126."

    STARTS_NEW = True


class PARRequestURIAuthorizationRequestTestSet(GETRequestTestSet, ClientIDTestSet):
    NUMBER = "1b"
    NAME = "Authorization Request with `request_uri`"
    DESCRIPTION = "Authorization Request after a Pushed Authorization Request."

    REQUEST_URI_EXPIRE_WARNING_AFTER = 30  # seconds
    REQUEST_URI_EXPIRE_FAILURE_AFTER = 180  # seconds
    USED_REQUEST_URIS_EXPIRATION = 60 * 60 * 24

    NOT_PERMITTED_PARAMETERS = {
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

    PERMITTED_PARAMETERS = {
        "client_id",
        "request_uri",
    }

    DUMMY_PARAMETER = "dummy_parameter"


    def t0020_predefined_parameter_present(self, payload, **_):
        if not self.DUMMY_PARAMETER in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The parameter `{self.DUMMY_PARAMETER}` is missing. Please take care to pass on **all** parameters from the `authorization_endpoint` configuration value.",
            )

        new_payload = {k: v for k, v in payload.items() if k != self.DUMMY_PARAMETER}

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The parameter `{self.DUMMY_PARAMETER}` is contained in the URL.",
            output_data={"payload": new_payload},
        )

    t0020_predefined_parameter_present.title = "Predefined parameter present in URL?"

    def t3010_has_request_uri_parameter(self, payload, **_):
        if not "request_uri" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request does not contain a `request_uri` parameter.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The request contains a `request_uri` parameter.",
            output_data={"request_uri": payload["request_uri"]},
        )

    t3010_has_request_uri_parameter.title = "Request URI parameter present?"
    t3010_has_request_uri_parameter.references = [
        (
            "RFC9126 - Pushed Authorization Requests, Section 2.1",
            "https://www.rfc-editor.org/rfc/rfc9126.html#section-2.1",
        ),
        (
            "yes® Relying Party Developer Guide, Signing Service, Section 3.2",
            "https://docs.verimi.de/openbanking/docs/rp-devguide/latest/QES/index.html#_pushed_authorization_request",
        ),
    ]

    def t3020_no_extra_parameters(self, payload, **_):
        # The request may only contain 'request_uri' and 'client_id' parameters.

        # Calculate set of extra parameters
        request_parameters = set(payload.keys())

        not_permitted_parameters = self.NOT_PERMITTED_PARAMETERS & request_parameters

        if not_permitted_parameters:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request contains the following parameters that should not be used after a Pushed Authorization Request:"
                + self._list_parameters(not_permitted_parameters)
                + "Please take care to pass on all parameters in the Pushed Authorization Request and only include `request_uri` and `client_id` in the front-end authorization request.",
            )

        unknown_parameters = request_parameters - self.PERMITTED_PARAMETERS

        if unknown_parameters:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                f"The request contains the following unknown parameters: "
                + self._list_parameters(unknown_parameters)
                + "Please take care to pass on all parameters in the Pushed Authorization Request and only include `request_uri` and `client_id` in the front-end authorization request.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The request contains only the parameters `request_uri` and `client_id`.",
        )

    t3020_no_extra_parameters.title = "No extra parameters in URL?"
    t3020_no_extra_parameters.references = [
        (
            "RFC9126 - Pushed Authorization Requests, Section 4",
            "https://www.rfc-editor.org/rfc/rfc9126.html#name-authorization-request",
        ),
        (
            "yes® Relying Party Developer Guide, Signing Service, Section 3.3",
            "https://docs.verimi.de/openbanking/docs/rp-devguide/latest/QES/index.html#_authorization_request",
        ),
    ]

    def t3030_request_uri_parameter_is_valid(self, request_uri, client_id, **_):
        session = self.session_manager.find(client_id, request_uri=request_uri)
        if session:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                f"The request contains a `request_uri` parameter with the value `{request_uri}`, for which there exists a session. ",
                output_data={"session": session},
            )

        return RPTestResult(
            RPTestResultStatus.FAILURE,
            f"The request contains a `request_uri` parameter with the value `{request_uri}`, which we do not recognize. "
            + "Please check the following things: \n\n"
            " 1. That the request_uri value was used exactly as provided in the response to the Pushed Authorization Request.  \n"
            " 1. That the request_uri was used immediately after it was issued. If you waited a long time before using the request_uri, or used an old request_uri value, the request_uri may have expired.  \n"
            " 1. That you used the same client_id in the Pushed Authorization Request and in the current request. \n"
            "\nPlease start a new Pushed Authorization Request to get a new request_uri. ",
        )

    t3030_request_uri_parameter_is_valid.title = (
        "Provided Request URI parameter is valid?"
    )

    def t3040_request_uri_has_not_expired(self, session, **_):
        # Calculate how long ago the session was created
        elapsed = int((datetime.utcnow() - session.created_at).total_seconds())

        if elapsed > self.REQUEST_URI_EXPIRE_FAILURE_AFTER:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The `request_uri` has expired. "
                f"It was created {elapsed} seconds ago. "
                "The `request_uri` should be used immediately after it was issued.",
            )

        if elapsed > self.REQUEST_URI_EXPIRE_WARNING_AFTER:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                f"The `request_uri` may have expired in practice. "
                f"It was created {elapsed} seconds ago. "
                "The `request_uri` should be used immediately after it was issued.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The `request_uri` has not expired. "
            f"It was created {elapsed} seconds ago.",
        )

    t3040_request_uri_has_not_expired.title = "Provided Request URI has not expired?"

    def t3050_request_uri_has_not_been_used(self, session, **_):
        if session.used_request_uri:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                "This `request_uri` has been used before. This will not work with real IDPs. "
                "`request_uri` values can only be used once.",
            )

        session.used_request_uri = True
        self.session_manager.store(session)

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "This `request_uri` has not been used before.",
        )

    t3050_request_uri_has_not_been_used.title = (
        "Provided Request URI has not been used before?"
    )
