from dataclasses import dataclass
from typing import Callable, Optional
from .tools import ACRValues


@dataclass
class RPManualTest:
    name: str
    description: str
    acceptance_condition: str
    how_to_fix: str
    requires: Optional[Callable] = None


RP_MANUAL_TESTS = {
    "General": {
        "m000_custom_user_details": RPManualTest(
            name="Custom user details",
            description="Gives the option to modify the ID Token and Userinfo response contents.",
            acceptance_condition="-",
            how_to_fix="-",
        ),
    },
    "Security / ID Token": {
        "m110_id_token_nonce": RPManualTest(
            name="Invalid Nonce in ID Token",
            description="The nonce in the ID Token is different from the one sent in the request. This simulates the result of a CSRF or authorization code injection attack.",
            acceptance_condition="The ID Token must not be accepted.",
            how_to_fix="Check that you have implemented all ID Token checks as per the developer guide.",
            requires=lambda session: "openid" in session.scopes_list and session.nonce,
        ),
        "m120_id_token_expired": RPManualTest(
            name="Expired ID Token",
            description="The time in the `exp` claim in the ID Token is in the past. This simulates the result of a CSRF or authorization code injection attack.",
            acceptance_condition="The ID Token must not be accepted.",
            how_to_fix="Check that you have implemented all ID Token checks as per the developer guide.",
            requires=lambda session: "openid" in session.scopes_list,
        ),
        "m130_id_token_aud_wrong": RPManualTest(
            name="Wrong Audience in the ID Token",
            description="The `aud` claim in the ID Token does not contain the correct client ID, but a wrong client ID.",
            acceptance_condition="The ID Token must not be accepted.",
            how_to_fix="Check that you have implemented all ID Token checks as per the developer guide.",
            requires=lambda session: "openid" in session.scopes_list,
        ),
        "m131_id_token_iss_wrong": RPManualTest(
            name="Wrong Issuer in the ID Token",
            description="The `iss` claim in the ID Token does not contain the issuer URL, but an invalid value.",
            acceptance_condition="The ID Token must not be accepted.",
            how_to_fix="Check that you have implemented all ID Token checks as per the developer guide.",
            requires=lambda session: "openid" in session.scopes_list,
        ),
        "m140_id_token_signature_using_wrong_key": RPManualTest(
            name="Invalid ID Token signature",
            description="The signing key of the ID Token does not match the published signing key of the IDP.",
            acceptance_condition="The ID Token must not be accepted.",
            how_to_fix="Check that you have implemented all ID Token checks as per the developer guide. ",
            requires=lambda session: "openid" in session.scopes_list,
        ),
        "m150_id_token_signature_alg_is_none": RPManualTest(
            name="Insecure ID Token signing algorithm",
            description="The signing algorithm of the ID Token is done using the algorithm `none`, effectively omitting the signature.",
            acceptance_condition="The ID Token must not be accepted.",
            how_to_fix="Check that you have implemented all ID Token checks as per the developer guide.",
            requires=lambda session: "openid" in session.scopes_list,
        ),
    },
    "Security / Authorization Response": {
        "m200_iss_is_wrong": RPManualTest(
            name="Invalid Issuer Identifier",
            description="The `iss` parameter in the authorization response is different from the issuer of the IDP. This simulates an IDP Mix-Up attack.",
            acceptance_condition="The authorization response must not be accepted.",
            how_to_fix="Check that you have implemented the check on the `iss` parameter as described in the developer guide.",
        ),
        "m201_iss_is_missing": RPManualTest(
            name="Missing Issuer Identifier",
            description="The `iss` parameter in the authorization response is missing. This simulates an IDP Mix-Up attack.",
            acceptance_condition="The authorization response must not be accepted.",
            how_to_fix="Check that you have implemented the check on the `iss` parameter as described in the developer guide.",
        ),
        "m210_state_is_wrong": RPManualTest(
            name="Invalid State in Response",
            description="The `state` parameter in the authorization response does not match the one in the authorization request. This simulates a CSRF attack. "
            "However, since either PKCE or Nonce are used as well, `state` is not strictly necessary for CSRF protection. "
            "Nonetheless, if you're using `state` for in-depth CSRF protection, your application should detect modified `state` values. "
            "If you have made the decision to use `state` to carry application state, you might want to "
            "ensure integrity, e.g., using a signature or MAC.",
            acceptance_condition="The authorization response must not be accepted (under the conditions listed).",
            how_to_fix="By default: The `state` value should be compared to the value stored in the user's browser session. "
            "When `state` is used only for carrying application state, integrity protection should be considered. ",
            requires=lambda session: session.state,
        ),
    },
    "Security / Authentication": {
        "m300_acr_wrong": RPManualTest(
            name="Single-factor authentication ACR value instead of 2FA",
            description=f"This test sets the parameter `acr` to `{ACRValues.DEFAULT}` in the ID Token, indicating that a single-factor-authentication was performed. "
            "To run this test, you must ask for 2FA in your request via `acr_values`.",
            acceptance_condition="If 2FA is critical for the use case, the ID Token must not be accepted.",
            how_to_fix="Always check that the `acr` parameter exists and is set to the value required for your use case. ",
            requires=lambda session: ACRValues.SCA in session.acr_values_list,
        ),
        "m310_acr_missing": RPManualTest(
            name="Missing ACR value",
            description="This test remove the parameter from the ID Token. "
            "To run this test, you must ask 2FA in your request via `acr_values`.",
            acceptance_condition="If 2FA is critical for the use case, the ID Token must not be accepted.",
            how_to_fix="Always check that the `acr` parameter exists and is set to the value required for your use case. ",
            requires=lambda session: ACRValues.SCA in session.acr_values_list,
        ),
    },
    "User Experience": {
        "m800_user_aborts": RPManualTest(
            name="User cancels transaction",
            description="The user clicks on 'abort' in the bank's user interface or declines to share data.",
            acceptance_condition="A non-technical message gives the user the option to try again, or to use a different bank or identification method.",
            how_to_fix="Check the section 'Avoiding Misleading Error Messages' in the developer guide.",
        ),
        "m810_select_different_bank": RPManualTest(
            name="User wants to select a different bank.",
            description="The user clicks on 'select a different bank' in the bank's user interface.",
            acceptance_condition="The user is being sent to the account chooser with the option to select a different bank.",
            how_to_fix="Check the section on the account chooser in the developer guide.",
        ),
        "m820_technical_error": RPManualTest(
            name="A technical error occurs during the OpenID flow.",
            description="During the user's interaction with the bank, a technical error occurs.",
            acceptance_condition="The user sees a helpful error message indicating and gets the option to try again.",
            how_to_fix="Check the section 'Avoiding Misleading Error Messages' in the developer guide.",
        ),
    },
}
