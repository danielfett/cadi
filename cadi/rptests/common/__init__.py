import json
import os

import jsonschema

SCHEMAS_PATH = os.path.abspath(os.path.dirname(__file__)) + "/../../../schemas"


def validate_with_json_schema(json_input, schema_filename):
    schema_path = os.path.join(SCHEMAS_PATH, schema_filename)
    with open(schema_path) as f:
        schema = json.load(f)
    try:
        jsonschema.validate(json_input, schema)
    except jsonschema.ValidationError as e:
        return False, str(e)
    return True, None
