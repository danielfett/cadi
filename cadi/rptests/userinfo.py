from cadi.rptests.common.client_authentication import \
    ClientAuthenticationTestSet
from cadi.rptests.common.requests import GETRequestTestSet


class UserinfoRequestTestSet(
    GETRequestTestSet,
    ClientAuthenticationTestSet,
):
    NUMBER = "3"
    NAME = "Userinfo Request"
    DESCRIPTION = "Userinfo Request as defined in OpenID Connect Core."
