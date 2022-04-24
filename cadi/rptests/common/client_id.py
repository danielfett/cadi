import re

from ...rptestmechanics import RPTestSet, RPTestResult, RPTestResultStatus
from ...tools import CLIENT_ID_PATTERN


class ClientIDTestSet(RPTestSet):
    def t1000_has_client_id(self, payload, **_):
        if not "client_id" in payload:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Client ID not found in payload. The parameter 'client_id' was expected.",
                skip_all_further_tests=True,
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "The 'client_id' parameter was found in the payload.",
                output_data={"client_id": payload["client_id"]},
            )

    t1000_has_client_id.title = "Client ID presence in payload"

    def t1001_client_id_is_valid(self, client_id, **_):
        if not re.match(CLIENT_ID_PATTERN, client_id):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Client ID '{client_id}' does not have the right format: sandbox.yes.com:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.",
                skip_all_further_tests=True,
            )

        client_config = self.platform_api.get_client_config_with_cache(client_id)
        if client_config is None:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Client ID '{client_id}' does not exist in the yes directory.",
                skip_all_further_tests=True,
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"Client ID '{client_id}' is of the correct format and was found in the yes® directory.",
            output_data={"client_config": client_config},
        )

    t1001_client_id_is_valid.title = "Client ID validity"

    def t1002_client_id_is_not_deactivated(self, client_config, **_):
        if client_config["status"] == "active":
            return RPTestResult(
                RPTestResultStatus.SUCCESS, "Client ID status is 'active'."
            )
        elif client_config["status"] == "inactive":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Client ID is in status 'inactive'. The client ID needs to be in status 'active' to be used. Contact yes® to fix the problem.",
                skip_all_further_tests=True,
            )
        elif client_config["status"] == "demo":
            return RPTestResult(
                RPTestResultStatus.WARNING,
                "Client ID is in status 'demo'. The client ID should be in status 'active' to be used. Contact yes® to fix the problem.",
            )
        else:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Client ID status is '{client_config['status']}'. The client ID needs to be in status 'active' to be used. Contact yes® to fix the problem.",
                skip_all_further_tests=True,
            )

    t1002_client_id_is_not_deactivated.title = "Client ID status"

    def t1003_client_id_is_unambiguous(self, client_id, expected_client_id, **_):
        if client_id != expected_client_id:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Client ID '{client_id}' does not match the client ID '{expected_client_id}' that was found somewhere else in the request. "
                "Please ensure that the client ID is unambiguous.",
                skip_all_further_tests=True,
            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            f"Client ID '{client_id}' is unambiguous (i.e., we did not find a different client ID somewhere else in the request).",
            output_data={"client_id": client_id},
        )

    t1003_client_id_is_unambiguous.title = "Client ID unambiguity"