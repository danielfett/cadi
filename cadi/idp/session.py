import base64
import random
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


def random_string_base64(length: int) -> str:

    return base64.urlsafe_b64encode(
        bytes(random.SystemRandom().getrandbits(8) for _ in range(length))
    ).decode("utf-8")


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
