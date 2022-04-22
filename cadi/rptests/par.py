import json
from ..rptestmechanics import RPTestResult, RPTestResultStatus

from .common.requests import POSTRequestTestSet, GETRequestTestSet
from .common.authorization_request import AuthorizationRequestTestSet
from .common.client_id import ClientIDTestSet
from .common.client_authentication import ClientAuthenticationTestSet


class PushedAuthorizationRequestTestSet(
    POSTRequestTestSet,
    AuthorizationRequestTestSet,
    ClientIDTestSet,
    ClientAuthenticationTestSet,
):
    NAME = "Pushed Authorization Request (RFC9126)"
    DESCRIPTION = "Backend Pushed Authorization Request as defined in RFC9126."



class PARRequestURIAuthorizationRequestTestSet(GETRequestTestSet, ClientIDTestSet):
    NAME = "Authorization Request following Pushed Authorization Request"
    DESCRIPTION = "Authorization Request after PAR."

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

    def t0002_has_request_uri_parameter(self, payload, **_):
        if not "request_uri" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request does not contain a 'request_uri' parameter.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The request contains a 'request_uri' parameter.",
        )

    t0002_has_request_uri_parameter.title = "Request URI parameter"
    t0002_has_request_uri_parameter.references = [
        (
            "RFC9126 - Pushed Authorization Requests, Section 2.1",
            "https://www.rfc-editor.org/rfc/rfc9126.html#section-2.1",
        ),
        (
            "yes® Relying Party Developer Guide, Signing Service, Section 3.2",
            "https://yes.com/docs/rp-devguide/latest/QES/index.html#_pushed_authorization_request",
        ),
    ]

    def t0003_no_extra_parameters(self, payload, **_):
        # The request may only contain 'request_uri' and 'client_id' parameters.

        # Calculate set of extra parameters
        request_parameters = set(payload.keys())

        not_permitted_parameters = self.NOT_PERMITTED_PARAMETERS & request_parameters

        if not_permitted_parameters:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The request contains the following parameters that should not be used after a Pushed Authorization Request: {', '.join(not_permitted_parameters)}. "
                "Please take care to pass on all parameters in the Pushed Authorization Request and only include request_uri and client_id in the traditional authorization request.",
            )

        unknown_parameters = request_parameters - self.PERMITTED_PARAMETERS

        if unknown_parameters:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                f"The request contains the following unknown parameters: {', '.join(unknown_parameters)}. "
                "Please take care to pass on all parameters in the Pushed Authorization Request and only include request_uri and client_id in the traditional authorization request.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The request contains only the parameters 'request_uri' and 'client_id'.",
        )

    t0003_no_extra_parameters.title = "No extra parameters"
    t0003_no_extra_parameters.references = [
        (
            "RFC9126 - Pushed Authorization Requests, Section 4",
            "https://www.rfc-editor.org/rfc/rfc9126.html#name-authorization-request",
        ),
        (
            "yes® Relying Party Developer Guide, Signing Service, Section 3.3",
            "https://yes.com/docs/rp-devguide/latest/QES/index.html#_authorization_request",
        ),
    ]

    def t0004_request_uri_parameter_is_valid(self, **_):
        pass
