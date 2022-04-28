from datetime import datetime

import cryptography

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
                "Client certificate was not presented in the TLS connection. "
                "You must ensure that your HTTP library uses your client certificate with your private key during the connection establishment to this endpoint. "
                "Note: Some libraries silently skip the use of the client certificate when the certificate or private key file cannot be found. ",
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "Some client certificate was presented in the TLS connection.",
                output_data={"client_certificate": request.headers[self.MTLS_HEADER]},
                extra_details=f"Presented client certificate:\n{request.headers[self.MTLS_HEADER]}",
            )

    t2000_client_certificate_present.title = "Client certificate presence"

    def t2001_client_certificate_format(self, client_certificate, **_):
        # Check if the client certificate is a valid x509 self-signed certificate
        try:
            cert = cryptography.x509.load_pem_x509_certificate(
                client_certificate.encode(), cryptography.default_backend()
            )
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "Client certificate is a valid x509 certificate.",
                output_data={"client_certificate_parsed": cert},
            )
        except Exception as e:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Client certificate is not a valid x509 certificate. "
                "Please see the yes® Developer Guide on how to create a certificate suitable for the ues with yes®.",
                extra_details=str(e),
            )

    t2001_client_certificate_format.title = "Client certificate format"
    t2001_client_certificate_format.references = [
        (
            "yes® Relying Party Developer Guide, Onboarding and Testing, Section 4.1",
            "https://yes.com/docs/rp-devguide/latest/ONBOARDING/index.html#_required_data",
        ),
    ]

    def t2002_client_certificate_valid(self, client_certificate_parsed, **_):
        # Check if the client certificate is a valid x509 self-signed certificate
        try:
            issuer = dict(client_certificate_parsed.get_issuer().get_components())
            subject = dict(client_certificate_parsed.get_subject().get_components())
            if (
                issuer["CN"] == subject["CN"]
                and issuer["O"] == subject["O"]
                and issuer["OU"] == subject["OU"]
                and issuer["C"] == subject["C"]
            ):
                return RPTestResult(
                    RPTestResultStatus.SUCCESS,
                    "Client certificate is a valid self-signed x509 certificate.",
                )
        except Exception as e:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "Client certificate is not a valid x509 self-signed certificate. "
                "Please see the yes® Developer Guide on how to create a self-signed certificate.",
                extra_details=str(e),
            )

        return RPTestResult(
            RPTestResultStatus.FAILURE,
            "Client certificate is not a valid x509 self-signed certificate. "
            "Please see the yes® Developer Guide on how to create a self-signed certificate.",
        )

    t2002_client_certificate_valid.title = "Client certificate validity"
    t2002_client_certificate_valid.references = [
        (
            "yes® Relying Party Developer Guide, Onboarding and Testing, Section 4.1",
            "https://yes.com/docs/rp-devguide/latest/ONBOARDING/index.html#_required_data",
        ),
    ]

    def t2003_client_certificate_matching(self, client_config, client_certificate, **_):
        # Compare the client certificate presented to the client certificates in the 'jwks' set of the client configuration. At least one must match.
        # The client configuration jwks contains the client certificate in PEM format in the x5c member of the JWKS.

        valid_client_certificates = client_config["jwks"]
        for valid_client_certificate in valid_client_certificates:
            if valid_client_certificate["x5c"][0] == client_certificate:
                return RPTestResult(
                    RPTestResultStatus.SUCCESS,
                    "Client certificate matches one of the registered client certificates.",
                )

        return RPTestResult(
            RPTestResultStatus.FAILURE,
            "Client certificate does not match any of the registered client certificates. "
            "Please ensure that you are using the correct client certificate that has been registered with yes®.",
            extra_details=f"Valid client certificates:\n{valid_client_certificates}",
        )

    t2003_client_certificate_matching.title = "Client certificate registered"
    t2003_client_certificate_matching.references = [
        (
            "yes® Relying Party Developer Guide, Onboarding and Testing, Section 4.1",
            "https://yes.com/docs/rp-devguide/latest/ONBOARDING/index.html#_required_data",
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
                RPTestResultStatus.SUCCESS, "Client certificate is not expired."
            )

    t2004_client_certificate_is_not_expired.title = "Client certificate expiration"
    t2004_client_certificate_is_not_expired.references = [
        (
            "yes® Relying Party Developer Guide, Onboarding and Testing, Section 4.1",
            "https://yes.com/docs/rp-devguide/latest/ONBOARDING/index.html#_required_data",
        ),
    ]
