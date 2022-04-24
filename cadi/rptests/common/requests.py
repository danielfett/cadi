from urllib.parse import parse_qs
from ...rptestmechanics import RPTestSet, RPTestResult, RPTestResultStatus


def dump_cherrypy_request_headers(request):
    return (
        f"{request.method} {request.path_info}{'?' if request.query_string != '' else ''}{request.query_string}\n"
        + "\n".join(c + ": " + v for c, v in request.headers.items())
    )


class POSTRequestTestSet(RPTestSet):
    def t0000_is_post_request(self, request, **_):

        request_info = {"Request Headers": dump_cherrypy_request_headers(request)}
        # request is a cherrypy.request object
        if request.method != "POST":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request method is not POST. This endpoint only accepts POST requests.",
                skip_all_further_tests=True,
                request_info=request_info,
            )
        else:
            request_info["Request Body"] = request.body.read()
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "The request method is POST.",
                request_info=request_info,
            )

    t0000_is_post_request.title = "Request method"

    def t0001_mime_type_is_form_encoded(self, request, **_):
        # request is a cherrypy.request object
        if "Content-Type" not in request.headers:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request does not contain a Content-Type header.",
            )

        if request.headers["Content-Type"] != "application/x-www-form-urlencoded":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The Content-Type header is not application/x-www-form-urlencoded, but '{request.headers['Content-Type']}'. "
                "This endpoint only accepts application/x-www-form-urlencoded requests. "
                "If you're using form encoding already, you might need to set the 'Content-Type' header to the correct value.",
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "The Content-Type header is application/x-www-form-urlencoded.",
            )

    t0001_mime_type_is_form_encoded.title = "Content-Type header"

    def t0002_body_encoded_correctly(self, request, **_):
        try:
            parsed = parse_qs(
                request.body.fullvalue(), strict_parsing=True, errors="strict"
            )
        except Exception as e:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The request body does not seem to be formatted correctly. This endpoint only accepts properly encoded URLs. The body must be form-encoded.",
                extra_details=str(e),
            )

        # ensure that in the parsed dict, each field only contains one value
        for key, value in parsed.items():
            if len(value) != 1:
                return RPTestResult(
                    RPTestResultStatus.FAILURE,
                    f"Each parameter must only be sent once. The parameter '{key}' is sent {len(value)} times.",
                )

        # use the first instance of each parameter in the output payload dict
        payload = {
            key: value[0]
            for key, value in parsed.items()
        }

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The request body is properly formatted.",
            output_data={"payload": payload},
        )

    t0002_body_encoded_correctly.title = "Request body"
    t0002_body_encoded_correctly.references = [
        ("RFC6749 - OAuth 2.0, Appendix B", "https://www.rfc-editor.org/rfc/rfc6749#appendix-B"),
    ]

    def t0003_no_parameters_in_query_string(self, request, **_):
        if request.query_string != "":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request contains a query string. Do not add parameters to the query string for this endpoint.",
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "The request does not contain a query string.",
            )

    t0003_no_parameters_in_query_string.title = "Query string"

class GETRequestTestSet(RPTestSet):
    def t0000_is_get_request(self, request, **_):
        request_info = {"Request Headers": dump_cherrypy_request_headers(request)}
        # request is a cherrypy.request object
        if request.method != "GET":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The request method is not GET, but '{request.method}'. This endpoint only accepts GET requests.",
                skip_all_further_tests=True,
                request_info=request_info,
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "The request method is GET.",
                request_info=request_info,
            )

    t0000_is_get_request.title = "Request Method"

    def t0010_request_url_assembled_correctly(self, request, **_):
        # request is a cherrypy.request object
        # check that the URL (cherrypy.request.query_string) is a valid form-encoded URL and does not contain parameters of the form '?n=true?foo=bar'

        if "?" in request.query_string:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The request URL does not seem to be formatted correctly. This endpoint only accepts properly encoded URLs. The part '{request.query_string}' must not contain a question mark.",
            )

        try:
            parsed = parse_qs(
                request.query_string, strict_parsing=True, errors="strict"
            )
        except Exception as e:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The request URL does not seem to be formatted correctly. This endpoint only accepts properly encoded URLs. The part '{request.query_string}' must be a valid form-encoded URL.",
                extra_details=str(e),
            )

        # ensure that in the parsed dict, each field only contains one value
        for key, value in parsed.items():
            if len(value) != 1:
                return RPTestResult(
                    RPTestResultStatus.FAILURE,
                    f"Each parameter must only be sent once. The parameter '{key}' is sent {len(value)} times.",
                )

        # use the first instance of each parameter in the output payload dict
        payload = {
            key: value[0]
            for key, value in parsed.items()
        }

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The request URL is properly formatted.",
            output_data={"payload": payload},
        )

    t0010_request_url_assembled_correctly.title = "Request URL"
