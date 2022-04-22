from .common.requests import GETRequestTestSet
from .common.authorization_request import AuthorizationRequestTestSet
from .common.client_id import ClientIDTestSet


class TraditionalAuthorizationRequestTestSet(
    GETRequestTestSet, ClientIDTestSet, AuthorizationRequestTestSet
):
    NAME = "RFC6749 Authorization Request"
    DESCRIPTION = "Traditional Authorization Request as defined in RFC6749."
