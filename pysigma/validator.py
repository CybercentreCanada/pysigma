import datetime
import yaml
import uuid
from .signatures import SignatureLoadError, load_signature, UnsupportedFeature
from pathlib import Path

MANDATORY_FIELDS = ['title', 'id', 'first_imported', 'sharing', 'source', 'reference', 'modified', 'detection']
OPTIONAL_FIELDS = ['tags', 'author', ]


def validate_date(date_text):
    try:
        if date_text != datetime.datetime.strptime(date_text, "%Y/%m/%d").strftime('%Y/%m/%d'):
            raise ValueError
        return True
    except ValueError:
        return False


def validate_uuid(value):
    # Checks if uuid complies with version 4 uuid
    try:
        uuid.UUID(str(value), version=4)
        return True
    except ValueError:
        return False


class SigmaReturn():
    def __init__(self, key, msg, description=None):
        self.msg = msg
        self.key = key
        self.description = description


class SigmaValidator():
    def __init__(self, data, raw_str):
        self.data = data
        self.raw_str = raw_str
        self.file_errors = []
        self.file_warnings = []
        self.sigma_rules = None
        self.edited_str = None

    def modify_values(self):
        # modifies fields that have errors
        for e in self.file_errors:
            # currently only the id is generated with a random UUID
            if isinstance(e.msg, str) and e.msg == 'id':
                id = uuid.uuid4()
                # Only want to modify first segment in data, multiple segments means multiple documents which is handled elsewhere
                modified_data = self.data[0]
                modified_data['id'] = str(id)
                self.edited_str = modified_data

    def validate_errors(self):
        errors = []
        for segment in self.data:
            for key in MANDATORY_FIELDS:
                if key not in segment:
                    errors.append(SigmaReturn('Missing field ', key))
        # Test signature load
        try:
            load_signature(self.raw_str)
        except SignatureLoadError as e:
            errors.append(SigmaReturn('Signature Load error', e))
        except UnsupportedFeature as e:
            errors.append(SigmaReturn('Unsupported feature ', e))
        return errors

    def validate_warnings(self):
        warnings = []
        for segment in self.data:
            for key in OPTIONAL_FIELDS:
                if key not in segment:
                    warnings.append(SigmaReturn('Missing optional field ', key))
        return warnings

    def validate_field_contents(self):
        VALID_STATUS_VALUES = ['testing', 'stable', 'experimental']
        VALID_LEVEL_VALUES = ['critical', 'high', 'medium', 'low']
        VALID_SHARING_VALUES = ['TLP:W', 'TLP:A', 'TLP:G']
        basic_fields = ['title', 'author', 'description']

        def check_values(key, value, key_to_check, valid_values):
            if key == key_to_check:
                if value not in valid_values:
                    self.file_errors.append(SigmaReturn(f'Invalid value ', key, f'must be one of {valid_values}'))
        # only consider first document in yaml file
        for key, value in self.data[0].items():
            if key in ['date', 'modified', 'first_imported']:
                if not validate_date(value):
                    self.file_errors.append(SigmaReturn('Invalid value ', key))
            if key == 'id':
                if not validate_uuid(value):
                    self.file_errors.append(SigmaReturn('Invalid value ', key))
            if key in basic_fields:
                if not isinstance(value, str):
                    self.file_errors.append(SigmaReturn('Invalid value type ', key))
            check_values(key, value, 'status', VALID_STATUS_VALUES)
            check_values(key, value, 'level', VALID_LEVEL_VALUES)
            check_values(key, value, 'sharing', VALID_SHARING_VALUES)

            # if key in field_types:
            #     #check if value matches type it should be
            #     expected_value_type = field_types[key]
            #     if not isinstance(value, expected_value_type):
            #         print(expected_value_type, 'problem', type(value))

    def return_file_error_state(self):
        """
        Checks for errors and returns true if any of the rules are in an error state
        :return: bool
        """
        error_state = False
        if self.file_errors:
            error_state = self.file_errors
            return error_state
        return error_state

    def return_file_warning_state(self):
        """
        Checks for warnings and returns true if any of the rules are in an warning state
        :return: bool
        """
        warning_state = False
        if self.file_warnings:
            warning_state = self.file_warnings
            return warning_state
        return warning_state

    def return_rule_errors_for_cmlt(self):
        if self.file_errors:
            error_string = self.__build_return_string_cmlt(self.file_errors)
        return error_string

    def __build_return_string_cmlt(self, collection):
        format_string = '{indent:>8} {key:30}  {value} \n {des:>92}'
        format_string_ex = '{indent:>8} {key:30}  {value}'

        return_string = '\n'.join([format_string.format(
            indent='-', key=e.key + ':', value=e.msg, des=e.description)
            if e.description else format_string_ex.format(
            indent='-', key=e.key + ':', value=e.msg) for e in collection])
        for err in collection:
            if err.description:
                format_string.format(indent='-', key=err.key + ':', value=err.msg, des=err.description)
        return return_string

    def return_rule_warnings_for_cmlt(self):
        warning_string = []
        if self.file_warnings:
            warning_string = self.__build_return_string_cmlt(self.file_warnings)
        return warning_string

    def return_original_rule(self):
        return self.raw_str

    def return_edited_file_string(self):
        return self.edited_str


def run_sigma_validator(sigma_path, generate_values):
    """
    This is the base function that should be called to validate a rule. It will take as an argument the file path,
        create a SigmaValidator object, parse that file to ensure all valid fields exists.
    :param sigma_path: The file variable passed in. Usually a string or Path variable
    :param generate_values: bool: Indicates whether to generate missing fields.
    :return:
    """
    if isinstance(sigma_path, str) or isinstance(sigma_path, Path):
        if isinstance(sigma_path, str):
            file_as_path = Path(sigma_path)
        else:
            file_as_path = sigma_path
        with open(file_as_path) as f:
            data = f.read()
            yaml_data = list(yaml.safe_load_all(data))
            validator = SigmaValidator(yaml_data, data)
            file_errors = validator.validate_errors()
            file_warnings = validator.validate_warnings()
            if file_errors:
                validator.file_errors = file_errors
            if file_warnings:
                validator.file_warnings = file_warnings
            validator.validate_field_contents()

    return validator
