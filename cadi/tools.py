from dataclasses import replace
from datetime import datetime, timedelta
import cryptography
from jwcrypto import jwk
from cryptography.hazmat.primitives.serialization import Encoding


CLIENT_ID_PATTERN = (
    r"sandbox.yes.com:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


def create_self_signed_certificate():
    """
    Create a self-signed certificate.
    """
    private_key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=cryptography.hazmat.backends.default_backend(),
    )
    public_key = private_key.public_key()

    builder = cryptography.x509.CertificateBuilder()
    builder = builder.subject_name(
        cryptography.x509.Name(
            [
                cryptography.x509.NameAttribute(
                    cryptography.x509.oid.NameOID.COMMON_NAME, "localhost"
                )
            ]
        )
    )
    builder = builder.issuer_name(
        cryptography.x509.Name(
            [
                cryptography.x509.NameAttribute(
                    cryptography.x509.oid.NameOID.COMMON_NAME, "localhost"
                )
            ]
        )
    )
    builder = builder.not_valid_before(datetime.today())
    builder = builder.not_valid_after(datetime.today() + timedelta(days=365))
    builder = builder.serial_number(cryptography.x509.random_serial_number())
    builder = builder.public_key(public_key)

    certificate = builder.sign(
        private_key=private_key,
        algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
        backend=cryptography.hazmat.backends.default_backend(),
    )

    return certificate, private_key


def convert_to_jwks(certificate):
    """
    Convert a certificate to a JWK.
    """
    public_key = certificate.public_key()
    public_key_jwk = jwk.JWK.from_public_key(public_key, alg="RS256")
    public_key_jwk.kid = "yes-sandbox-client-id"
    public_key_jwk.use = "sig"
    public_key_jwk.x5c = [certificate.public_bytes(Encoding.PEM).decode("utf-8")]
    return public_key_jwk


MAX_RETRIES_CHECK_AND_SET = 7


def insert_into_cache_list(cache, key, item, max_entries, expire, replace_by_key=None):
    for i in range(MAX_RETRIES_CHECK_AND_SET):
        # Retry loop, limited to some reasonable retries
        the_list, cas_key = cache.gets(key)
        if the_list is None:
            the_list = [item]
            cache.set(key, the_list, expire=expire)
            return
        else:
            if replace_by_key:
                for e in the_list:
                    if getattr(e, replace_by_key) == getattr(item, replace_by_key):
                        the_list.remove(e)

            # Insert latest result on the top
            the_list.insert(0, item)

            # Truncate the list to the max number of results
            the_list = the_list[:max_entries]

            if cache.cas(key, the_list, expire=expire, cas=cas_key):
                return

    raise Exception("Could not insert data item into cache")
