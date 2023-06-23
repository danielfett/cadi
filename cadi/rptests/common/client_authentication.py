from base64 import b64decode
from collections import OrderedDict
from datetime import datetime

import cryptography
from asn1crypto import x509
from ruamel.yaml import YAML
from ruamel.yaml.compat import StringIO

from ...rptestmechanics import RPTestResult, RPTestResultStatus, RPTestSet


class ClientAuthenticationTestSet(RPTestSet):
    MTLS_HEADER = "X-ARR-ClientCert"

    client_certificate = None
    client_certificate_parsed = None

    def t2000_client_certificate_present(self, request, **_):
        if (
            not self.MTLS_HEADER in request.headers
            or request.headers[self.MTLS_HEADER] == ""
        ):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Your client certificate was not presented in the TLS connection. "
                "You must ensure that your HTTP library uses your client certificate with your private key during the connection establishment to this endpoint (TLS Client Authentication). "
                "This problem is often caused by one of the following: \n\n"
                "  * Some libraries silently skip the use of the client certificate when the certificate or private key file cannot be found. "
                "Please ensure that you passed the **certificate and private key** to the HTTP library and that the files can be found by the library.\n"
                "  * If there is a proxy that intercepts TLS connections between you and the endpoint, the proxy cannot pass the client certificate to the endpoint. "
                "During development, this is often the case when there is **endpoint security software** on your machine or a **company firewall** that intercepts TLS connections. "
                "Please check if there is a proxy, endpoint security software, or a company firewall between you and the endpoint. "
                "Click on your browser's lock icon and view the details of the certificate: If the certificate for yes® CADI shows an issuer other than Microsoft, you are probably behind a TLS intercepting proxy.",
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "A client certificate was presented in the TLS connection.",
                output_data={"client_certificate": request.headers[self.MTLS_HEADER]},
                #extra_details=f"Presented client certificate:\n{request.headers[self.MTLS_HEADER]}",
            )

    t2000_client_certificate_present.title = "TLS client certificate present?"

    def t2001_client_certificate_format(self, client_certificate, **_):
        # Check if the client certificate is a valid x509 self-signed certificate
        try:
            n = 64
            splitted_lines = "\n".join(
                client_certificate[i : i + n]
                for i in range(0, len(client_certificate), n)
            )
            cert = cryptography.x509.load_pem_x509_certificate(
                (
                    "-----BEGIN CERTIFICATE-----\n"
                    + splitted_lines
                    + "\n-----END CERTIFICATE-----"
                ).encode(),
                cryptography.hazmat.backends.default_backend(),
            )

            # For dumping, load the certificate using asn1crypto;
            # might want to merge this with the above.
            signature_object = x509.Certificate.load(b64decode(client_certificate))
            yaml = YAML(typ="unsafe", pure=True)
            yaml.Representer.add_representer(OrderedDict, yaml.Representer.represent_dict)
            yaml.default_flow_style = False
            # dump to string
            dumped_cert = StringIO()
            yaml.dump(signature_object.native, dumped_cert)

            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "Client certificate is a valid x509 certificate.",
                output_data={"client_certificate_parsed": cert},
                request_info={"Client certificate": self._code(dumped_cert.getvalue())},
            )

        except Exception as e:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Client certificate is not a valid x509 certificate. "
                "Please see the yes® Developer Guide on how to create a certificate suitable for the ues with yes®. Error: \n"  + self._code(str(e)),
            )

    t2001_client_certificate_format.title = "Client certificate is a valid x509 certificate?"
    t2001_client_certificate_format.references = [
        (
            "yes® Relying Party Developer Guide, Onboarding and Testing, Section 4.1",
            "https://docs.verimi.de/openbanking/docs/rp-devguide/latest/ONBOARDING/index.html#_required_data",
        ),
    ]

    def t2002_client_certificate_valid(self, client_certificate_parsed, **_):
        # Check if the client certificate is a valid x509 self-signed certificate
        try:
            issuer = {
                x.rfc4514_attribute_name: x.value
                for x in client_certificate_parsed.issuer
            }
            subject = {
                x.rfc4514_attribute_name: x.value
                for x in client_certificate_parsed.subject
            }
            if issuer == subject:
                return RPTestResult(
                    RPTestResultStatus.SUCCESS,
                    "Client certificate is a self-signed x509 certificate.",
                )
            else:
                return RPTestResult(
                    RPTestResultStatus.FAILURE,
                    "Client certificate is not a self-signed x509 certificate (see details). "
                    "Please see the yes® Developer Guide on how to create a certificate suitable for the ues with yes®.",
                    extra_details=f"Issuer:\n{issuer}\nSubject:\n{subject}",
                )
        except Exception as e:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Client certificate is not a valid self-signed x509 certificate. "
                "Please see the yes® Developer Guide on how to create a self-signed certificate. Error: \n"  + self._code(str(e)),
            )

    t2002_client_certificate_valid.title = "Client certificate is self-signed?"
    t2002_client_certificate_valid.references = [
        (
            "yes® Relying Party Developer Guide, Onboarding and Testing, Section 4.1",
            "https://docs.verimi.de/openbanking/docs/rp-devguide/latest/ONBOARDING/index.html#_required_data",
        ),
    ]

    def t2003_client_certificate_matching(self, client_config, client_certificate, **_):
        # Compare the client certificate presented to the client certificates in the 'jwks' set of the client configuration. At least one must match.
        # The client configuration jwks contains the client certificate in PEM format in the x5c member of the JWKS.

        valid_client_certificates = client_config["jwks"]
        for valid_client_certificate in valid_client_certificates["keys"]:
            if valid_client_certificate["x5c"][0] == client_certificate:
                return RPTestResult(
                    RPTestResultStatus.SUCCESS,
                    "Client certificate matches one of the registered client certificates.",
                )

        return RPTestResult(
            RPTestResultStatus.FAILURE,
            "Client certificate does not match any of the registered client certificates. "
            "Please ensure that you are using the correct client certificate that has been registered with yes®.",
        )

    t2003_client_certificate_matching.title = "Client certificate registered?"
    t2003_client_certificate_matching.references = [
        (
            "yes® Relying Party Developer Guide, Onboarding and Testing, Section 4.1",
            "https://docs.verimi.de/openbanking/docs/rp-devguide/latest/ONBOARDING/index.html#_required_data",
        ),
    ]

    def t2004_client_certificate_is_not_expired(self, client_certificate_parsed, **_):
        # Check if the client certificate is not expired
        if client_certificate_parsed.not_valid_after < datetime.utcnow():
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"Client certificate is expired (not valid after = {client_certificate_parsed.not_valid_after}). Please contact yes® with a new client certificate (see references).",
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS, "Client certificate has not expired."
            )

    t2004_client_certificate_is_not_expired.title = "Client certificate not expired?"
    t2004_client_certificate_is_not_expired.references = [
        (
            "yes® Relying Party Developer Guide, Onboarding and Testing, Section 4.1",
            "https://docs.verimi.de/openbanking/docs/rp-devguide/latest/ONBOARDING/index.html#_required_data",
        ),
    ]
