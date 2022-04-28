from dataclasses import dataclass
import json
import os
from typing import Optional

USER_DATA_PATH = (
    os.path.abspath(os.path.dirname(__file__)) + "/../../ext/userDetails.json"
)


@dataclass
class Claim:
    name: str
    can_be_verified: bool
    is_typically_available: bool
    note: str = ""
    userdata_name: Optional[str] = None
    transform_fn: callable = lambda x: x

    def extract(self, data_source):
        raw = data_source.get(self.userdata_name or self.name, None)
        return self.transform_fn(raw)


_yes_claims = (
    Claim("email", False, False),
    Claim("email_verified", False, False),
    Claim("phone_number", False, True),
    Claim("phone_number_verified", False, True),
    Claim("given_name", True, True),
    Claim("family_name", True, True),
    Claim("gender", False, True),
    Claim(
        "salutation", False, True, userdata_name="https://www.yes.com/claims/salutation"
    ),
    Claim("title", False, False, userdata_name="https://www.yes.com/claims/title"),
    Claim(
        "place_of_birth",
        True,
        True,
        userdata_name="https://www.yes.com/claims/place_of_birth",
    ),
    Claim("birthdate", True, True),
    Claim(
        "nationalities",
        True,
        True,
        userdata_name="https://www.yes.com/claims/nationality",
        transform_fn=lambda x: [x] if x else None,
    ),
    Claim("address", True, True),
    Claim(
        "https://www.yes.com/claims/preferred_iban",
        True,
        True,
        note="While requested as 'unverified', this claim is always verified and not editable by the user.",
    ),
    Claim(
        "https://www.yes.com/claims/tax_id",
        True,
        False,
        note="While requested as 'unverified', this claim is always verified and not editable by the user.",
    ),
)

YES_CLAIMS = {c.name: c for c in _yes_claims}
YES_VERIFIED_CLAIMS = {c.name: c for c in _yes_claims if c.can_be_verified}


class ClaimsProvider:
    def __init__(self):
        with open(USER_DATA_PATH, "r") as f:
            self.users = json.loads(f.read())

    def get_all_users(self):
        return self.users

    def _get_user_data(self, user_id):
        for user in self.users:
            if user["user_id"] == user_id:
                return user

        raise Exception(f"User with user_id '{user_id}' not found.")

    def process_ekyc_request(self, user_id, session, endpoint, minimal):
        user = self._get_user_data(user_id)

        r = session.claims.get(endpoint, {})
        rvc = r.get("verified_claims", {})  # /verified_claims
        rvcc = rvc.get("claims", {})  # /verified_claims/claims
        rvcv = rvc.get("verification", {})  # /verified_claims/verification

        output = {}
        verified_claims_output = {}

        for c in YES_CLAIMS.values():
            val = c.extract(user)
            if c.name in r and (not minimal or c.is_typically_available):
                output[c.name] = val
            if (
                c.name in rvcc
                and c.can_be_verified
                and (not minimal or c.is_typically_available)
            ):
                verified_claims_output[c.name] = val

        verification_output = {}

        if "trust_framework" in rvcv:
            verification_output["trust_framework"] = "de_aml"

        if len(verified_claims_output) and len(verification_output):
            output["verified_claims"] = {
                "claims": verified_claims_output,
                "verification": verification_output,
            }

        if "txn" in r:
            output["txn"] = session.sid

        output["sub"] = user["user_id"]

        return output
