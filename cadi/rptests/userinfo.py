from cadi.rptestmechanics import RPTestResult, RPTestResultStatus
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

    def t3000_openid_in_scopes(self, session, **_):
        if not "openid" in session.scopes_list:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The authorization request did not contain the `openid` scope. "
                "To use the userinfo endpoint, your authorization request must include the scope `openid`.",

            )

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The authorization request contained the `openid` scope.",
        )

    t3000_openid_in_scopes.title = "`openid` scope present?"
