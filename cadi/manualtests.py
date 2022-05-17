from dataclasses import dataclass


@dataclass
class RPManualTest:
    name: str
    description: str
    acceptance_condition: str
    how_to_fix: str
    implemented: bool = False


RP_MANUAL_TESTS = {
    "General": {
        "m000_custom_user_details": RPManualTest(
            "Custom user details",
            "Gives the option to modify the ID Token and Userinfo response contents.",
            "-",
            "-",
            True,
        ),
    },
    "Security / ID Token": {
        "m011_id_token_nonce": RPManualTest(
            "Invalid Nonce in ID Token",
            "The nonce in the ID Token is different from the one sent in the request. This simulates the result of a CSRF or authorization code injection attack.",
            "The ID Token must not be accepted.",
            "Check that you have implemented all ID Token checks as per the developer guide.",
        ),
        "m012_id_token_expired": RPManualTest(
            "Expired ID Token",
            "The time in the `exp` claim in the ID Token is in the past. This simulates the result of a CSRF or authorization code injection attack.",
            "The ID Token must not be accepted.",
            "Check that you have implemented all ID Token checks as per the developer guide.",
        ),
        "m013_id_token_aud_wrong": RPManualTest(
            "Wrong Audience in the ID Token",
            "The `aud` claim in the ID Token does not contain the correct client ID, but a wrong client ID.",
            "The ID Token must not be accepted.",
            "Check that you have implemented all ID Token checks as per the developer guide.",
        ),
        "m014_id_token_signature_using_wrong_key": RPManualTest(
            "Wrong ID Token signature",
            "The ID Token does not contain a valid signature.",
            "The ID Token must not be accepted.",
            "Check that you have implemented all ID Token checks as per the developer guide. ",
        ),
        "m015_id_token_signature_alg_is_none": RPManualTest(
            "Insecure ID Token signing algorithm",
            "The signing algorithm of the ID Token is done using the algorithm `none`, effectively omitting the signature.",
            "The ID Token must not be accepted.",
            "Check that you have implemented all ID Token checks as per the developer guide.",
        ),
        "m016_id_token_signature_using_wrong_key": RPManualTest(
            "Wrong key for ID Token signature",
            "The signing key of the ID Token does not match the published signing key of the IDP.",
            "The ID Token must not be accepted.",
            "Check that you have implemented all ID Token checks as per the developer guide.",
        ),
    },
    "Security / Authorization Response": {
        "m020_iss_is_wrong": RPManualTest(
            "Invalid Issuer Identifier",
            "The `iss` parameter in the authorization response is different from the issuer of the IDP. This simulates an IDP Mix-Up attack.",
            "The authorization response must not be accepted.",
            "Check that you have implemented the check on the `iss` parameter as described in the developer guide.",
        ),
        "m021_state_is_wrong": RPManualTest(
            "Invalid State in Response",
            "The `state` parameter in the authorization response does not match the one in the authorization request. This simulates a CSRF attack. "
            "However, since either PKCE or Nonce are used as well, `state` is not strictly necessary for CSRF protection. "
            "Nonetheless, if you're using `state` for in-depth CSRF protection, your application should detect modified `state` values. "
            "If you have made the decision to use `state` to carry application state, you might want to "
            "ensure integrity, e.g., using a signature or MAC.",
            "The authorization response must not be accepted (under the conditions listed).",
            "By default: The `state` value should be compared to the value stored in the user's browser session. "
            "When `state` is used only for carrying application state, integrity protection should be considered. ",
        ),
    },
    "Security / Authentication": {
        "m030_acr_wrong": RPManualTest(
            "1FA ACR value",
            "This test sets the parameter `acr` to `https://www.yes.com/acrs/online_banking` in the ID Token, indicating that a single-factor-authentication was performed. ",
            "If 2FA is critical for the use case, the ID Token must not be accepted.",
            "Always check that the `acr` parameter is set to the value required for your use case. ",
        ),
        "m031_acr_missing": RPManualTest(
            "Missing ACR value",
            "This test remove the parameter from the ID Token. ",
            "If 2FA is critical for the use case, the ID Token must not be accepted.",
            "Always check that the `acr` parameter is set to the value required for your use case. ",
        ),
    },
    "User Experience": {
        "m080_user_aborts": RPManualTest(
            "User cancels transaction",
            "The user clicks on 'abort' in the bank's user interface or declines to share data.",
            "A non-technical message gives the user the option to try again, or to use a different bank or identification method.",
            "Check the section 'Avoiding Misleading Error Messages' in the developer guide.",
        ),
        "m081_select_different_bank": RPManualTest(
            "User wants to select a different bank.",
            "The user clicks on 'select a different bank' in the bank's user interface.",
            "The user is being sent to the account chooser with the option to select a different bank.",
            "Check the section on the account chooser in the developer guide.",
        ),
        "m082_technical_error": RPManualTest(
            "A technical error occurs during the OpenID flow.",
            "During the user's interaction with the bank, a technical error occurs.",
            "The user sees a helpful error message indicating and gets the option to try again.",
            "Check the section 'Avoiding Misleading Error Messages' in the developer guide.",
        ),
    },
}
