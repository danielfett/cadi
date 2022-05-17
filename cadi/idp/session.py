from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from cadi.tools import random_string_base64


@dataclass
class IDPSession:
    client_id: str
    redirect_uri: str
    response_type: str
    scopes_list: Optional[List[str]]
    claims: Dict[str, Dict]
    state: Optional[str]
    nonce: Optional[str]
    code_challenge: Optional[str]
    code_challenge_method: Optional[str]
    authorization_details: Optional[Dict]

    used_request_uri: bool = False
    used_code: bool = False

    id_token_response_contents: Optional[Dict] = None
    userinfo_response_contents: Optional[Dict] = None

    # Our internal identifier
    sid: str = field(default_factory=lambda: random_string_base64(16))

    # Create a random request_uri for each session, consisting of a fixed prefix and 16 random bytes
    request_uri: str = field(
        default_factory=lambda: f"urn:ietf:params:oauth:request_uri:"
        + random_string_base64(16)
    )

    # Create an authorization code
    authorization_code: str = field(default_factory=lambda: random_string_base64(16))

    # Create an access token
    access_token: str = field(default_factory=lambda: random_string_base64(16))

    # Store the creation timestamp
    created_at: float = field(default_factory=lambda: datetime.utcnow())

    # Store the issuance time of the authorization code
    code_issued_at: Optional[float] = None

    # If a manual test case was selected, store the test case
    test_case: Optional[str] = None


class SessionManager:
    MAX_OPEN_SESSIONS_PER_CLIENT = 10
    SESSION_EXPIRATION = 60 * 60 * 3  # 3 hours

    def __init__(self, cache):
        self.cache = cache

    def store(self, session: IDPSession):
        # Store the session in the list of sessions for the client_id in the cache
        key = ("sessions", session.client_id)
        self.cache.insert_into_list(
            key,
            session,
            self.MAX_OPEN_SESSIONS_PER_CLIENT,
            self.SESSION_EXPIRATION,
            replace_by_key="sid",
        )

        # Store also a mapping from access tokens to client_ids
        key = ("at_to_client", session.access_token)
        self.cache.set(
            key,
            session.client_id,
            self.SESSION_EXPIRATION,
        )

    def find(
        self,
        client_id,
        sid=None,
        authorization_code=None,
        request_uri=None,
        access_token=None,
    ):
        # Check if a session with this data exists for the given client_id
        key = ("sessions", client_id)
        the_list = self.cache.get(key, default=[])

        # Check if the session with the given sid exists in the list
        for s in the_list:
            if (
                (not sid or sid == s.sid)
                and (
                    not authorization_code or authorization_code == s.authorization_code
                )
                and (not request_uri or request_uri == s.request_uri)
                and (not access_token or access_token == s.access_token)
            ):
                return s

        return None

    def find_by_access_token(self, access_token):
        key = ("at_to_client", access_token)

        client_id = self.cache.get(key)

        if client_id is None:
            return None

        else:
            return self.find(client_id=client_id, access_token=access_token)
