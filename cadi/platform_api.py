import requests


class PlatformAPI:
    EXPIRE_CLIENT_CONFIG = 3600

    TIMEOUT = 30  # seconds
    DEFAULT_URLS = {
        "sandbox": {
            "token_endpoint": "https://as.sandbox.openbanking.verimi.cloud/token",
            "rps": "https://api.sandbox.openbanking.verimi.cloud/rps/v1/",
        },
        "production": {
            "token_endpoint": "https://as.openbanking.verimi.de/token",
            "rps": "https://api.openbanking.verimi.de/rps/v1/",
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
        return client_config


class DummyAPI:
    def get_client_config_with_cache(self, client_id):
        return {
            "subject_type": "public",
            "response_types": ["code"],
            "client_name": "yes® Public Demo Client",
            "default_consent_purpose": "Registration",
            "client_id": client_id,
            "ac_redirect_uri": "http://localhost:3000/yes/accb",
            "redirect_uris": ["http://localhost:3000/yes/oidccb"],
            "allowed_scopes": ["openid"],
            "allowed_claims": [
                "sub",
                "verified_claims",
                "birthdate",
                "https://www.yes.com/claims/nationality",
                "gender",
                "https://www.yes.com/claims/title",
                "nationalities",
                "title",
                "email",
                "https://www.yes.com/claims/place_of_birth",
                "https://www.yes.com/claims/preferred_iban",
                "email_verified",
                "address",
                "https://www.yes.com/claims/salutation",
                "https://www.yes.com/claims/delivery_address",
                "phone_number_verified",
                "txn",
                "given_name",
                "https://www.yes.com/claims/tax_id",
                "birth_given_name",
                "https://www.yes.com/claims/transaction_id",
                "place_of_birth",
                "birth_family_name",
                "phone_number",
                "birth_middle_name",
                "salutation",
                "family_name",
            ],
            "allowed_claims_qes": [],
            "token_endpoint_auth_method": "self_signed_tls_client_auth",
            "jwks": {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "173603377803273411445213032488946426602474235558",
                        "x5c": [
                            "MIIFLTCCAxWgAwIBAgIUHmilCrqBdzRNwiMsKjJXMu4U5qYwDQYJKoZIhvcNAQELBQAwJjEkMCIGA1UEAwwbeWVzw4LCriBzYW5kYm94IGRlbW8gY2xpZW50MB4XDTIxMDQyMTA4NDYyOVoXDTQ4MTIxMTA4NDYyOVowJjEkMCIGA1UEAwwbeWVzw4LCriBzYW5kYm94IGRlbW8gY2xpZW50MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxuPtaJ4XRPYybN27MK5YBWLKV/dEHPfG2B6iUYz/DOJkm487jBE86oTfUb9noK7R4+A7/iN4aEdtv2kKg0tpF1v2pwsNHQR4FiVK+zrI58PIhexQ18WI+wSbkalZ2rCtsUOYK2v4yibmURuQdRpLAdHl/SiQyAJKK1bLWWFDyvPALtM9dx1wyLxgxetotfRxOR2Df0fMbCwD0hQpWWWJUaskY36nCsAuoWj2cQ3UhEnhWDP51LI2ZPIowq8/ZTbmuYgedj4afr4auv6+Vu6JJ35hvOL5j4VNnAfjEsOJYZ0k3HopWqYohSEJUyEiQ74I9fP8oKn1Qx5MdNaFZS/jxMSRyI/Eebts59+k4QK0EOP5Irr8xG6Xf2DqpjZQSPw0BOOC9VAfO9QHQNZMcOrOeecjigVLa7qpJMBYSgjBRHIqeB1r3CMCLythGVAzxSi8EwmSLdo7suSITqi+Rcb9QQ7fiw4G0UDsxIRHCTi9FZvJYeEHykJ0aDzqozEzov97TKdf9riczurVOxXJGd1WPD31bfSodXz/FBDu/NsEbmIxQPOHKxQkbvwo1w0M2oytq2enjTcwTKAZaqWEgfOk0JyxO1vOERnRj+Jk/b7YbYliPpxRec+Xzyz990j4fsjRDitUtqskGxpn7fdcwMTw+iJWLySJWYUYlNh2TUmEwfECAwEAAaNTMFEwHQYDVR0OBBYEFD2ItbpMrr8BTFt+K+PNf5PMFnXgMB8GA1UdIwQYMBaAFD2ItbpMrr8BTFt+K+PNf5PMFnXgMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAEFzfSzvxD8sf2BaKk+DYC+qigC3Si+grprqx1WMh0jp84zBYDmKW6LRoDDFDXmP6YE0AT3hyKL7bB3zAiT7LPVwIx4YLgAYEYLqUbRwhBCahQZG4jUxUWCM+bQTk7zlVlD3r6+47fFD8EEPxK0QmsF/fB9KVKxlJdgT7pXebO4zAyCPMBRaz3PFW8CKaqoPanvppzwTqmbxuMH2YdrPigAV2Xqy88d11y9tqOLRL3mgSjm6z9+BwEwfF7rrgYhI776rOi6cJiXpDNHyYhOtg3WBqPssG/x0TwP51R82FG20YXLRFwMKdqA8Fnzd+VmzPbUaLrAUNbJmd3brSMU0WJXQVwAXEb65N2M+6gSfxtkNJOzxplJipXUKSBnxq9HhWPTxHyjo0V/G8tOU9gWbOZvkO28wgIchbJoBFgqtemosbXq77uo5Eue8jxd8E7IWjCbv7i4MvpZ/1WsJ+8WhW+g11q4+4AxPZsr4LUOaoC8E8sOBrKWQKgZTsf3oVfRi1350kr/87+vXiM/1scQLU4JUyARp5g8btlC2r7PIH9Qo8FYdlwig+trxiTI+fbM16PgeIwyFa29FK2Iy1gUswyjrgdwo+GDLJNBYlPq+FCQ8+3e3F6t76nx8GbZ71T/gPTPr7vpLdOeksMw3aMbx9wSouz33nEaq5Zs69wA2AHeb"
                        ],
                        "x5t#S256": "JX50qAD0Za84F2UW91nHnoV561-P4B-4ob6bagFeq6Y",
                        "n": "xuPtaJ4XRPYybN27MK5YBWLKV_dEHPfG2B6iUYz_DOJkm487jBE86oTfUb9noK7R4-A7_iN4aEdtv2kKg0tpF1v2pwsNHQR4FiVK-zrI58PIhexQ18WI-wSbkalZ2rCtsUOYK2v4yibmURuQdRpLAdHl_SiQyAJKK1bLWWFDyvPALtM9dx1wyLxgxetotfRxOR2Df0fMbCwD0hQpWWWJUaskY36nCsAuoWj2cQ3UhEnhWDP51LI2ZPIowq8_ZTbmuYgedj4afr4auv6-Vu6JJ35hvOL5j4VNnAfjEsOJYZ0k3HopWqYohSEJUyEiQ74I9fP8oKn1Qx5MdNaFZS_jxMSRyI_Eebts59-k4QK0EOP5Irr8xG6Xf2DqpjZQSPw0BOOC9VAfO9QHQNZMcOrOeecjigVLa7qpJMBYSgjBRHIqeB1r3CMCLythGVAzxSi8EwmSLdo7suSITqi-Rcb9QQ7fiw4G0UDsxIRHCTi9FZvJYeEHykJ0aDzqozEzov97TKdf9riczurVOxXJGd1WPD31bfSodXz_FBDu_NsEbmIxQPOHKxQkbvwo1w0M2oytq2enjTcwTKAZaqWEgfOk0JyxO1vOERnRj-Jk_b7YbYliPpxRec-Xzyz990j4fsjRDitUtqskGxpn7fdcwMTw-iJWLySJWYUYlNh2TUmEwfE",
                        "e": "AQAB",
                    }
                ]
            },
            "owner_id": "133874",
            "policy_uri": "https://yes.com/privacy",
            "logo_uri": "https://logos.yes.com/Sandbox/sandbox.yes.com_e85ff3bc-96f8-4ae7-b6b1-894d8dde9ebe.png",
            "status": "active",
            "application_type": "native",
            "grant_types": ["authorization_code"],
            "allowed_authorization_data_types": ["payment_initiation"],
        }
