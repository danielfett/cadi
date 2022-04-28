import re

import cherrypy
from cadi.tools import CLIENT_ID_PATTERN

from ..rptestmechanics import RPTestResultStatus

TEST_RESULT_STATUS_MAPPING = {
    RPTestResultStatus.SUCCESS: {
        "text": "Success",
        "color": "success",
        "description": "The feature is used correctly",
        "icon": "check-circle",
    },
    RPTestResultStatus.WARNING: {
        "text": "Warning",
        "color": "warning",
        "description": "The current usage of the feature may lead to problems in practice",
        "icon": "exclamation-circle",
    },
    RPTestResultStatus.FAILURE: {
        "text": "Failure",
        "color": "danger",
        "description": "This will lead to an error in practice",
        "icon": "exclamation-circle",
    },
    RPTestResultStatus.SKIPPED: {
        "text": "Test was skipped",
        "color": "secondary",
        "description": "There was no need to run this test or the prerequisites are not met",
        "icon": "slash-circle",
    },
    RPTestResultStatus.INFO: {
        "text": "Info",
        "color": "info",
        "description": "Informative - not indicating a problem",
        "icon": "info-circle",
    },
    RPTestResultStatus.WAITING: {
        "text": "Waiting",
        "color": "primary",
        "description": "The test is waiting for a prerequisite to be met",
        "icon": "question-circle",
    },
}


class UserInterface:
    def __init__(self, platform_api, cache, j2env):
        self.platform_api = platform_api
        self.cache = cache
        self.j2env = j2env

    @cherrypy.expose
    def index(self, client_id=None, error=None):
        # Check if the client ID matches the right format
        if client_id and not re.match(CLIENT_ID_PATTERN, client_id):
            client_id = None

        # Render the index.html.j2 template
        template = self.j2env.get_template("index.html")
        return template.render(
            client_id=client_id,
            error=error,
        )

    @cherrypy.expose
    def log(self, client_id):
        client_config = self._get_client_config(client_id)

        test_results = self.cache.get(("test_results", client_id), default=[])
        # test_results.reverse() - results in arbitrary order - strange!
        tr_reversed = test_results[::-1]

        # Mapping from RPTestResultStatus to text, bootstrap text color, description and icon

        # Render the index.html.j2 template
        template = self.j2env.get_template("log.html")
        return template.render(
            client_id=client_id,
            client_config=client_config,
            test_results=tr_reversed,
            id=id,
            Status=RPTestResultStatus,
            SM=TEST_RESULT_STATUS_MAPPING,
            iss=f"{ cherrypy.request.base }/idp",
            len=len,
        )

    def _get_client_config(self, client_id):
        # Client-IDs are all lowercase
        client_id = client_id.lower()

        # Check if the client_id has the correct format of sandbox.yes.com:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        if not re.match(
            CLIENT_ID_PATTERN,
            client_id,
        ):
            # Redirect to the index page with a parameter saying that the client_id is invalid
            raise cherrypy.HTTPRedirect(
                f"/?client_id={client_id}&error=invalid_client_id_format"
            )

        client_config = self.platform_api.get_client_config_with_cache(client_id)
        if client_config is None:
            # Redirect to the index page with a parameter saying that the client_id is invalid
            raise cherrypy.HTTPRedirect(
                f"/?client_id={client_id}&error=invalid_client_id"
            )
        return client_config
