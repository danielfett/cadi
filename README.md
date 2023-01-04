# Conformance, Acceptance, and Debug Test IDP (CADI)

yes® CADI is a service that enables testing of implementations on conformance with the yes® specifications. It can also help to debug any problems with implementations by providing concise and clear error messages. CADI is furthermore used during UI/UX reviews to generate test cases like error conditions.

## What CADI is and what it isn't

 * CADI implements an identity provider (IDP) interface according to the yes® specifications.
 * CADI is extremely lenient in what it accepts as requests. It will accept requests that would not work with a real bank and that do not comply with the yes® specifications.
 * For any deviation from the specification, or wherever things might go wrong in practice, CADI will provide warnings or error messages that try to be as clear as possible, e.g., by providing the exact reason why a request would have been rejected in a real-world scenario.
 * Since CADI does not handle any personal data and is available in the sandbox only, it can provide detailed error messages even for security-sensitive areas, e.g., if a wrong client ID is used or client authentication is missing.

yes® CADI works well with the identity service, but is (currently) limited for signing and payment initiation. In the latter two, it can be used to check the pushed authorization request and the authorization request, but signing and payment initiation processes cannot be completed.

## How to run

Install the requirements:
    
    pip install -r requirements.txt

Create a file `platform-credentials.yml` containing the credentials for accessing the yes® platform with the following contents:

    client_id: "yes-sandbox-platform-client-id"
    cert: "cert.pem"
    key: "key.pem"
    environment: sandbox

Make sure `client.pem` and `key.pem` exist and contain the respective credentials.

Run the server:

    python -m cadi.main platform-credentials.yml
