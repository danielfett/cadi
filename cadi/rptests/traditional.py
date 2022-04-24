from cadi.rptestmechanics import RPTestResult, RPTestResultStatus
from .common.requests import GETRequestTestSet
from .common.authorization_request import AuthorizationRequestTestSet
from .common.client_id import ClientIDTestSet


class TraditionalAuthorizationRequestTestSet(
    GETRequestTestSet, ClientIDTestSet, AuthorizationRequestTestSet
):
    NAME = "RFC6749 Authorization Request"
    DESCRIPTION = "Traditional Authorization Request as defined in RFC6749."

    DUMMY_PARAMETER = "dummy_parameter"

    def t0020_predefined_parameter_present(self, payload, **_):
        if not "predefined_parameter" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The parameter '{self.DUMMY_PARAMETER}' is missing. Please take care to pass on all parameters from the authorization_endpoint configuration.",
            )

        new_payload = {k: v for k, v in payload if k != self.DUMMY_PARAMETER}

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The parameter '{self.DUMMY_PARAMETER}' is contained in the URL.",
            output_data={"payload": new_payload},
        )
