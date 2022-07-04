from cadi.rptestmechanics import RPTestResult, RPTestResultStatus

from .common.authorization_request import AuthorizationRequestTestSet
from .common.client_id import ClientIDTestSet
from .common.requests import GETRequestTestSet

from json import dumps


class TraditionalAuthorizationRequestTestSet(
    GETRequestTestSet, ClientIDTestSet, AuthorizationRequestTestSet
):
    NUMBER = "1"
    NAME = "Authorization Request"
    DESCRIPTION = "Traditional Authorization Request as defined in RFC6749."
    STARTS_NEW = True

    DUMMY_PARAMETER = "dummy_parameter"

    QUERY_STRING_WARN_LENGTH_MAX = 2048
    QUERY_STRING_WARN_LENGTH = QUERY_STRING_WARN_LENGTH_MAX - len(
        "https://www.sparkasse-uelzen-luechow-dannenberg.de/de/home/onlinebanking/service/yes-Zustimmung.html?"
    )

    def t0011_request_url_length(self, request, **_):
        query_string_length = len(request.query_string)
        if query_string_length > self.QUERY_STRING_WARN_LENGTH_MAX:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                f"The authorization endpoint URL including your GET parameters is {query_string_length} characters long. "
                "Many browsers and firewalls only support URLs up to 2048 characters. "
                "Try to shorten the URL, e.g., by removing white space from the claims parameter and reducing the length of other parameters. "
                "If the problem persists, consider using Pushed Authorization Requests (see references).",
            )

        if query_string_length > self.QUERY_STRING_WARN_LENGTH:
            return RPTestResult(
                RPTestResultStatus.WARNING,
                f"The authorization endpoint URL including your GET parameters is {query_string_length} characters long. "
                "Many browsers and firewalls only support URLs up to 2048 characters, a limit that you can reach with some of the yes® banks. "
                "Try to shorten the URL, e.g., by removing white space from the claims parameter and reducing the length of other parameters. "
                "If the problem persists, consider using Pushed Authorization Requests (see references).",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The authorization endpoint URL is {query_string_length} characters long, which is within the limits of what most browsers and firewalls can handle.",
        )

    t0011_request_url_length.references = [
        (
            "RFC9126, OAuth 2.0 Pushed Authorization Requests",
            "https://www.rfc-editor.org/rfc/rfc9126.html",
        ),
    ]
    t0011_request_url_length.title = "Request URL length OK?"

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

    def t3024_claims_parameter_length(self, payload, claims_parsed, **_):
        # Check if there is unnecessary white space in the claims parameter.

        reencoded = dumps(claims_parsed, separators=(",", ":"))
        len_diff = len(payload["claims"]) - len(reencoded)
        if len_diff > 3:
            return RPTestResult(
                RPTestResultStatus.INFO,
                f"The claims parameter contains unnecessary white space. You can save {len_diff} characters by removing the white space.",
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"The claims parameter contains no unnecessary white space.",
        )

    t3024_claims_parameter_length.title = "No unnecessary white space in claims parameter?"
