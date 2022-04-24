
from cadi.rptestmechanics import RPTestResult, RPTestResultStatus
from cadi.rptests.common.client_authentication import ClientAuthenticationTestSet
from cadi.rptests.common.requests import GETRequestTestSet


class UserinfoRequestTestSet(
    GETRequestTestSet,
    ClientAuthenticationTestSet,
):
    NAME = "OpenID Connect Userinfo Request"
    DESCRIPTION = "Userinfo Request as defined in OpenID Connect Core."
