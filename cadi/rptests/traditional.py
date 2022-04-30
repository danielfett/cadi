from cadi.rptestmechanics import RPTestResult, RPTestResultStatus

from .common.authorization_request import AuthorizationRequestTestSet
from .common.client_id import ClientIDTestSet
from .common.requests import GETRequestTestSet


class TraditionalAuthorizationRequestTestSet(
    GETRequestTestSet, ClientIDTestSet, AuthorizationRequestTestSet
):
    NUMBER = "1"
    NAME = "Authorization Request"
    DESCRIPTION = "Traditional Authorization Request as defined in RFC6749."
    STARTS_NEW = True

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