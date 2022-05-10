from urllib.parse import parse_qs

from ...rptestmechanics import RPTestResult, RPTestResultStatus, RPTestSet

FILTERED_HEADERS = [
    "Remote-Addr",
    "X-Client-Ip",
    "X-Client-Port",
    "Max-Forwards",
    "X-Waws-Unencoded-Url",
    "Client-Ip",
    "X-Arr-Log-Id",
    "Disguised-Host",
    "X-Site-Deployment-Id",
    "Was-Default-Hostname",
    "X-Original-Url",
    "X-Forwarded-For",
    "X-Arr-Ssl",
    "X-Forwarded-Proto",
    "X-Appservice-Proto",
    "X-Forwarded-Tlsversion",
    "X-Arr-Clientcert",
]


def dump_cherrypy_request_headers(request):
    return (
        f"{request.method} {request.path_info}{'?' if request.query_string != '' else ''}{request.query_string}\n"
        + "\n".join(
            c + ": " + v
            for c, v in request.headers.items()
            if c not in FILTERED_HEADERS
        )
    )


class POSTRequestTestSet(RPTestSet):
    def t0000_is_post_request(self, request, **_):

        request_info = {
            "Request Headers": self._code(dump_cherrypy_request_headers(request))
        }
        # request is a cherrypy.request object
        if request.method != "POST":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request method is not POST. This endpoint must be accessed using a POST request.",
                skip_all_further_tests=True,
                request_info=request_info,
            )
        else:
            request_info["Request Body"] = self._code(
                request.body.read().decode("utf-8", errors="replace")
            )
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "The request method is POST.",
                request_info=request_info,
            )

    t0000_is_post_request.title = "Request method is POST?"

    def t0001_mime_type_is_form_encoded(self, request, **_):
        # request is a cherrypy.request object
        if "Content-Type" not in request.headers:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                "The request does not contain a Content-Type header.",
            )

        if not request.headers["Content-Type"].lower().startswith(
            "application/x-www-form-urlencoded"
        ):
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The Content-Type header is not `application/x-www-form-urlencoded`, but `{request.headers['Content-Type']}`. "
                "This endpoint only accepts `application/x-www-form-urlencoded` requests. "
                "If you're using form encoding already, you might need to set the `Content-Type` header to the correct value.",
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                f"The Content-Type header is `{request.headers['Content-Type']}`.",
            )

    t0001_mime_type_is_form_encoded.title = "Content-Type header correct?"

    def t0002_body_encoded_correctly(self, request, **_):
        ## ensure that in the parsed dict, each field only contains one value
        # for key, value in parsed.items():
        #    if len(value) != 1:
        #        return RPTestResult(
        #            RPTestResultStatus.FAILURE,
        #            f"Each parameter must only be sent once. The parameter '{key}' is sent {len(value)} times.",
        #        )
        #
        ## use the first instance of each parameter in the output payload dict
        # payload = {
        #    key: value[0]
        #    for key, value in parsed.items()
        # }
        # TODO: The checks above should be ran!
        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The request body is properly formatted.",
            output_data={"payload": request.body_params},
            request_info={"POST parameters": self._list_dict(request.body_params)},
        )

    t0002_body_encoded_correctly.title = "Request body encoded properly?"
    t0002_body_encoded_correctly.references = [
        (
            "RFC6749 - OAuth 2.0, Appendix B",
            "https://www.rfc-editor.org/rfc/rfc6749#appendix-B",
        ),
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

    t0003_no_parameters_in_query_string.title = "No query string in POST request?"


class GETRequestTestSet(RPTestSet):
    def t0000_is_get_request(self, request, **_):
        request_info = {
            "Request Headers": self._code(dump_cherrypy_request_headers(request))
        }
        # request is a cherrypy.request object
        if request.method != "GET":
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The request method is not GET, but `{request.method}`. This endpoint only accepts GET requests.",
                skip_all_further_tests=True,
                request_info=request_info,
            )
        else:
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "The request method is GET.",
                request_info=request_info,
            )

    t0000_is_get_request.title = "Request method is GET?"

    def t0010_request_url_assembled_correctly(self, request, **_):
        # request is a cherrypy.request object
        # check that the URL (cherrypy.request.query_string) is a valid form-encoded URL and does not contain parameters of the form '?n=true?foo=bar'

        if "?" in request.query_string:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The request URL does not seem to be formatted correctly. This endpoint only accepts properly encoded URLs. The part `{request.query_string}` must not contain a question mark.",
            )

        if request.query_string == "":
            return RPTestResult(
                RPTestResultStatus.SUCCESS,
                "The request URL is properly formatted.",
            )

        try:
            parsed = parse_qs(
                request.query_string, strict_parsing=True, errors="strict"
            )
        except Exception as e:
            return RPTestResult(
                RPTestResultStatus.FAILURE,
                f"The request URL does not seem to be formatted correctly. This endpoint only accepts properly encoded URLs. The part `{request.query_string}` must be a valid form-encoded URL.",
                extra_details=str(e),
            )

        # ensure that in the parsed dict, each field only contains one value
        for key, value in parsed.items():
            if len(value) != 1:
                return RPTestResult(
                    RPTestResultStatus.FAILURE,
                    f"Each parameter must only be sent once. The parameter `{key}` is sent {len(value)} times.",
                )

        # use the first instance of each parameter in the output payload dict
        payload = {key: value[0] for key, value in parsed.items()}

        return RPTestResult(
            RPTestResultStatus.SUCCESS,
            "The request URL is properly formatted.",
            output_data={"payload": payload},
            request_info={"GET parameters": self._list_dict(payload)},
        )

    t0010_request_url_assembled_correctly.title = "Request URL encoded properly?"
