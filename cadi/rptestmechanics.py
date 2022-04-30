import inspect
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from cadi.idp.session import SessionManager


class RPTestResultStatus(Enum):
    SUCCESS = "success"
    WARNING = "warning"
    FAILURE = "failure"
    SKIPPED = "skipped"
    INFO = "info"
    WAITING = "waiting"


@dataclass
class RPTestResult:
    result: str
    text: str
    skip_all_further_tests: bool = False
    test_id: Optional[str] = None
    title: Optional[str] = None
    extra_details: Optional[str] = None
    request_info: Dict[str, str] = field(default_factory=dict)
    output_data: Optional[Dict] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    service_information: Optional[Dict] = field(default_factory=dict)


@dataclass
class RPTestResultSet:
    test_results: List[RPTestResult]
    test: "RPTestSet"

    # Timestamp is set when creating the object
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def get_collected_request_info(self) -> Dict[str, str]:
        """
        Collects all request info from all test results and returns it as a dict.
        """
        collected_request_info = {}
        for test_result in self.test_results:
            collected_request_info.update(test_result.request_info)
        return collected_request_info

    def get_collected_service_information(self) -> Dict[str, str]:
        """
        Collects all service information from all test results and returns it as a dict.
        """
        collected_service_information = {}
        for test_result in self.test_results:
            collected_service_information.update(test_result.service_information)
        return collected_service_information

    def get_stats(self):
        """
        Returns a dict with the following keys:
        - success: number of successful tests
        - failure: number of failed tests
        - warning: number of warning tests
        - skipped: number of skipped tests
        - info: number of info tests
        - waiting: number of waiting tests
        """
        stats = {
            RPTestResultStatus.SUCCESS: 0,
            RPTestResultStatus.FAILURE: 0,
            RPTestResultStatus.WARNING: 0,
            RPTestResultStatus.SKIPPED: 0,
            RPTestResultStatus.INFO: 0,
            RPTestResultStatus.WAITING: 0,
        }
        for test_result in self.test_results:
            stats[test_result.result] += 1
        return stats


"""
An RP Test Set contains functions of the form t1234_ that are called by the
run() method in the lexical order of the function names. The number therefore
defines the order of the tests.

The convention for the number is as follows:
 * the first digit is the class of the test (0=basic request, 1=identifying the
   calling client, 2=client authentication, 3..=content checks)
 * the second and third digits can be used to group the tests (e.g., all tests
   around the claims parameter)
 * the fourth digit is the test number within the group
"""


class RPTestSet:
    TEST_NAME_PATTERN = re.compile("^t[0-9]{4}_")

    NAME: str
    DESCRIPTION: str
    STARTS_NEW: bool = False

    # data is a dict holding data to be persisted between tests
    data: Dict

    def __init__(self, platform_api, cache, **data):
        self.platform_api = platform_api
        self.cache = cache
        self.data = data
        self.session_manager = SessionManager(cache)

    def run(self):
        # Sort tXXX_* functions
        test_function_names = sorted(
            [
                function_name
                for function_name in dir(self)
                if self.TEST_NAME_PATTERN.match(function_name)
            ]
        )

        # We collect test results in an array to later produce an RPTestResultSet
        test_results = []

        # Run all functions
        skip_all_further_tests = False
        for function_name in test_function_names:
            # fn is the actual function object
            fn = getattr(self, function_name)

            # If skip_all_further_tests is set, the test is not run, but an empty test result is created.
            # If not all required data values are available, the test is skipped as well.
            if skip_all_further_tests or not self._all_data_available(fn):
                # Create empty test result
                result = RPTestResult(
                    result=RPTestResultStatus.SKIPPED,
                    text="Test skipped: An earlier test failed or this test is not relevant.",
                )
            else:
                # Actually run test
                result = fn(**self.data)
                if result is None:
                    result = RPTestResult(
                        result=RPTestResultStatus.SKIPPED,
                        text="Test returned no result.",
                    )

            # Augment result data with information from the test function
            result.test_id = function_name
            result.title = getattr(fn, "title", function_name)
            result.references = getattr(fn, "references", [])

            # Update the data with the result
            self.data.update(result.output_data)
            if result.skip_all_further_tests:
                skip_all_further_tests = True

            # Add result to the list of test results
            test_results.append(result)

        # Create RPTestResultSet
        return RPTestResultSet(
            test_results=test_results,
            test=self,
        )

    def _all_data_available(self, fn):
        fn_parameters = inspect.signature(fn).parameters
        for varname, details in fn_parameters.items():
            # Skip self and the catch-all parameter
            if varname in ["self", "_"]:
                continue

            # Skip parameters that have a default value
            if details.default != inspect.Parameter.empty:
                continue

            # Bail out if the parameter is not available
            if varname not in self.data:
                print(f"{fn}: Missing required data value '{varname}'")
                return False
        return True

    @staticmethod
    def _code(text):
        return "```\n" + text + "\n```"

    @staticmethod
    def _list_parameters(params):
        return "\n" + "".join(f"\n  * `{p}`" for p in params) + "\n\n"

    @staticmethod
    def _list(things, enumerated=False):
        if enumerated:
            return "\n" + "".join(f"\n 1. {t}" for t in things) + "\n\n"
        else:
            return "\n" + "".join(f"\n * {t}" for t in things) + "\n\n"