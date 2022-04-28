import requests


class PlatformAPI:
    EXPIRE_CLIENT_CONFIG = 3600

    TIMEOUT = 30  # seconds
    DEFAULT_URLS = {
        "sandbox": {
            "token_endpoint": "https://as.sandbox.yes.com/token",
            "rps": "https://api.sandbox.yes.com/rps/v1/",
        },
        "production": {
            "token_endpoint": "https://as.yes.com/token",
            "rps": "https://api.yes.com/rps/v1/",
        },
    }

    def __init__(self, client_id, cert, key, environment, cache):
        self.client_id = client_id
        self.cert_pair = (cert, key)
        self.environment = environment
        self.cache = cache

    def _get_access_token(self):
        req = requests.post(
            self.DEFAULT_URLS[self.environment]["token_endpoint"],
            data={"grant_type": "client_credentials", "client_id": self.client_id},
            cert=self.cert_pair,
            timeout=self.TIMEOUT,
        )
        response = req.json()
        return response["access_token"], response["expires_in"]

    def get_client_config(self, client_id, is_retry=False):
        expire_info = None
        if not (at := self.cache.get("access_token")):
            at, expire_info = self._get_access_token()

        try:
            req = requests.get(
                self.DEFAULT_URLS[self.environment]["rps"] + f"/{client_id}",
                headers={"Authorization": f"Bearer {at}"},
                cert=self.cert_pair,
                timeout=self.TIMEOUT,
            )
            req.raise_for_status()
            # If no error was raised, and the access token was new, store it in cache.
            if expire_info:
                self.cache.set("access_token", at, expire=expire_info)
            return req.json()
        # Catch errors
        except requests.exceptions.HTTPError as e:
            # Catch 404 not found error, return None
            if e.response.status_code == 404:
                return None
            # Catch 401 unauthorized HTTP error, invalidate access token, retry.
            if e.response.status_code == 401:
                self.cache.delete("access_token")
                if is_retry:
                    raise e
                return self.get_client_config(client_id, is_retry=True)
            else:
                raise e

    def get_client_config_with_cache(self, client_id):
        # Check if this client_id is in the cache
        if not (client_config := self.cache.get(("client_config", client_id))):
            # Get client configuration from directory
            try:
                client_config = self.get_client_config(client_id)
            except requests.exceptions.HTTPError as e:
                raise e
            if client_config is None:
                return None

            # Store client configuration in cache
            self.cache.set(
                ("client_config", client_id),
                client_config,
                expire=self.EXPIRE_CLIENT_CONFIG,
            )
        print (repr(client_config))
        return client_config

class DummyAPI:
    def get_client_config_with_cache(self, client_id):
        ....