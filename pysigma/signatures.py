import os
from typing import Dict, List, IO, Union, Any, Optional, Callable, Tuple
import base64
import re

import yaml

from .exceptions import UnsupportedFeature
from .parser import prepare_condition


class SignatureLoadError(KeyError):
    pass


# TODO We need to support the rest of them
SUPPORTED_MODIFIERS = {
    'contains',
    'all',
    'base64',
    # 'base64offset'
    'endswith',
    'startswith',
    # 'utf16le',
    # 'utf16be',
    # 'wide',
    # 'utf16',
    # 're',
}


Query = Optional[Union[str, re.Pattern]]
DetectionMap = Dict[
    str,
    Tuple[List[Query], List[str]]
]


def process_field_name(field_string):
    name_and_modifiers = field_string.split('|')
    name = name_and_modifiers.pop(0)
    modifiers = [_m for _m in name_and_modifiers if _m]
    unsupported = set(modifiers) - SUPPORTED_MODIFIERS
    if unsupported:
        raise UnsupportedFeature(f"Unsupported field modifiers used: {unsupported}")
    return name, modifiers


_NSC = NON_SPECIAL_CHARACTERS = r'[^\\*?]*'
ESCAPED_SPECIAL_CHARACTER = r'(?:\\[*?])'
ESCAPED_OTHER_CHARACTER = r'(?:\\[^*?])'
ESCAPED_WILDCARD_PATTERN = re.compile(fr'(?:{_NSC}{ESCAPED_SPECIAL_CHARACTER}*{ESCAPED_OTHER_CHARACTER})*')

UPTO_WILDCARD = re.compile(r'^([^\\?*]+|(?:\\[^?*\\])+)+')


def sigma_string_to_regex(original_value: str):
    value = original_value
    full_content = []
    while value:
        # Grab any content up to the first wildcard
        match = UPTO_WILDCARD.match(value)
        if match:
            # The non regex content in the sigma string, may have characters special to regex
            matched = match.group(0)
            full_content.append(re.escape(matched))
            value = value[len(matched):]
        elif value.startswith('*'):
            full_content.append('.*')
            value = value[1:]
        elif value.startswith('\\*'):
            full_content.append(re.escape('*'))
            value = value[2:]
        elif value.startswith('?'):
            full_content.append('.')
            value = value[1:]
        elif value.startswith('\\?'):
            full_content.append(re.escape('?'))
            value = value[2:]
        elif value.startswith(r'\\*'):
            full_content.append(re.escape('\\') + '.*')
            value = value[3:]
        elif value.startswith(r'\\?'):
            full_content.append(re.escape('\\') + '.')
            value = value[3:]
        elif value.startswith('\\'):
            full_content.append(re.escape('\\'))
            value = value[1:]
        else:
            raise ValueError(f"Could not parse string matching pattern: {original_value}")

    return re.compile(''.join(full_content), flags=re.IGNORECASE)  # Sigma strings are case insensitive


def apply_modifiers(value: str, modifiers: List[str]) -> Query:
    """
    Apply as many modifiers as we can during signature construction
    to speed up the matching stage as much as possible.
    """

    # If there are wildcards, or we are using the regex modifier, compile the query
    # string to a regex pattern object
    if 're' in modifiers:
        value = re.compile(value)

    if not ESCAPED_WILDCARD_PATTERN.fullmatch(value):
        # Transform the unescaped wildcards to their regex equivalent
        value = sigma_string_to_regex(value).pattern
    # Apply base64 encoding
    for mod in modifiers:
        if mod == 'base64':
            value = base64.encodebytes(value.encode()).decode()
        elif mod == 'contains':
            value = '.*' + value + '.*'
        elif mod == 'endswith':
            value = '.*' + value
        elif mod == 'startswith':
            value = value + '.*'

    # If we are just doing a full string compare of a raw string, the comparison
    # is case-insensitive in sigma, so all direct string comparisons will be lowercase.
    value = str(value).replace('\\*', '*').replace('\\?', '?')
    return value.lower()


class DetectionField:
    def __init__(self, list_search=None, map_search=None):
        self.list_search: List[Query] = list_search
        self.map_search: List[DetectionMap] = map_search


def normalize_field_map(field: Dict[str, Any]) -> DetectionMap:
    out: DetectionMap = {}
    for raw_key, value in field.items():
        key, modifiers = process_field_name(raw_key)
        if value is None:
            out[key] = [None], modifiers
        elif isinstance(value, list):
            if key not in out:
                out[key] = [
                    apply_modifiers(str(_v), modifiers) if _v is not None else None
                    for _v in value
                ], modifiers
            else:
                # if key already exists don't overwrite it.
                modifiers.append('all')
                out[key] = (out[key][0] + ([apply_modifiers(str(_v), modifiers) if _v is not None else None
                                for _v in value]), out[key][1] + (modifiers))
                # out[key].append([apply_modifiers(str(_v), modifiers) if _v is not None else None
                #                for _v in value], modifiers)
        else:
            if key not in out:
                out[key] = [apply_modifiers(str(value), modifiers)], modifiers
            else:
                # if key already exists don't overwrite it.
                modifiers.append('all')
                out[key] = (out[key][0] + ([apply_modifiers(str(value), modifiers)]), out[key][1] + (modifiers))


    return out


def normalize_field_block(name: str, field: Any) -> DetectionField:
    if isinstance(field, dict):
        return DetectionField(map_search=[normalize_field_map(field)])

    if isinstance(field, list):
        if all(isinstance(_x, dict) for _x in field):
            return DetectionField(map_search=[normalize_field_map(_x) for _x in field])
        return DetectionField(list_search=[apply_modifiers(str(_x), ['contains']) for _x in field])

    raise ValueError(f"Failed to parse selection field {name}: {field}")


def normalize_detection(detection: Dict[str, Any]) -> Dict[str, DetectionField]:
    return {
        name: normalize_field_block(name, data)
        for name, data in detection.items()
    }


class Detection:
    def __init__(self, data):
        detection = data['detection']
        self.logsource = data.get('logsource')
        self.timeframe = detection.pop('timeframe', None)

        self.condition = None
        if 'condition' in detection:
            self.condition = prepare_condition(detection.pop('condition'))

        self.detection = normalize_detection(detection)


class Signature:
    def __init__(self, data: List[Dict], file_name: str):
        self.title = None
        self.file_name = file_name
        self.description = None
        self.level = None
        self.tags = None
        self.detections = []
        self.id = None
        self.signature_source = None

        for segment in data:
            if 'title' in segment:
                self.title = segment['title']
            if 'description' in segment:
                self.description = segment['description']
            if 'level' in segment:
                self.level = segment['level']
            if 'tags' in segment:
                self.tags = segment['tags']
            if 'id' in segment:
                self.id = segment['id']
            if 'signature_source' in segment:
                self.signature_source = segment['signature_source']
            if 'detection' in segment:
                self.detections.append(Detection(segment))

                # The sigma spec repeatedly uses examples where the condition
                # is in the wrong place relative to the rest of the standard
                # so catch that here I suppose
                if self.detections[-1].condition is None and 'condition' in segment:
                    self.detections[-1].condition = prepare_condition(segment['condition'])

        if self.title is None:
            raise SignatureLoadError('title')
        #if self.signature_source is None:
        #    raise SignatureLoadError('signature_source')
        if len(self.detections) == 0:
            raise SignatureLoadError('detection')
        if len(self.detections) > 1:
            raise UnsupportedFeature('Multiple YAML documents unsupported (Multiple Detections)')

    def get_condition(self) -> Callable:
        return self.detections[0].condition

    def get_all_searches(self) -> Dict[str, DetectionField]:
        return dict(self.detections[0].detection)

    def get_search_fields(self, search_id) -> DetectionField:
        return self.detections[0].detection.get(search_id)

    def get_timeframe(self):
        return self.detections[0].timeframe


def load_signatures(signature_dir) -> Dict[str, Signature]:
    """
    Load all Sigma signatures from a directory

    :param signature_dir: Directory which contains all Sigma signature to load
    :return: A dictionary containing all loaded signatures
    """

    try:
        newdict = {}
        for files in os.listdir(signature_dir):
            dirfile = os.path.join(signature_dir, files)
            if os.path.isfile(dirfile):
                with open(dirfile, 'r') as yaml_in:
                    signature = load_signature(yaml_in)
                    newdict[signature.title] = signature
        return newdict

    except Exception:
        raise KeyError("Error in Formatting of Rules: Verify your YAML documents")


def load_signature(signature_file: Union[IO, str]) -> Signature:
    """
    Load a single sigma signature from a file object

    TODO introduce caching at this layer?

    :param signature_file: a file like object containing sigma yaml
    :return: Signature object
    """
    try:
        source = signature_file.name
    except AttributeError:
        source = '__str__'

    return Signature(list(yaml.safe_load_all(signature_file)), file_name=source)


# def escape_compatible(detect):
#     r"""
#     Looks through a yaml signature detection section and replaces all escape characters with just the characters to be
#     compatible ( i.e. \\ --> \ )
#
#     :param detect: dict, detection section of the yaml signature
#     :return: dict, fixed detection section
#     """
#
#     # check for dict
#     if isinstance(detect, dict):
#         # check all items in dict
#         for k, v in detect.items():
#             # check for dict
#             if isinstance(v, dict):
#                 # check all items in dict
#                 for k1, v1 in v.items():
#                     # check for list
#                     if isinstance(v1, list):
#                         count = 0
#                         for item in v1:
#                             if re.search(r'\\\\', str(item)):
#                                 try:
#                                     detect[k][k1][count] = item.replace('\\\\', '\\')
#                                 except:
#                                     pass
#
#                             elif re.search(r'\\?', str(item)) and not re.search(r'\\\?\\', str(item)):
#                                 try:
#                                     detect[k][k1][count] = item.replace('\\?', '?')
#                                 except:
#                                     pass
#                             count += 1
#
#                     # if item is just a string
#                     elif re.search(r'\\\\', str(v1)):
#                         try:
#                             detect[k][k1] = v1.replace('\\\\', '\\')
#                         except:
#                             pass
#
#                     elif re.search(r'\\?', str(v1)) and not re.search(r'\\\?\\', str(v1)):
#                         try:
#                             detect[k][k1] = v1.replace('\\?', '?')
#                         except:
#                             pass
#
#             # check for list
#             elif isinstance(v, list):
#                     count = 0
#                     for item in v:
#                         if re.search(r'\\\\', str(item)):
#                             try:
#                                 detect[k][count] = item.replace('\\\\', '\\')
#                             except:
#                                 pass
#
#                         elif re.search(r'\\?', str(item)) and not re.search(r'\\\?\\', str(item)):
#                             try:
#                                 detect[k][count] = item.replace('\\?', '?')
#                             except:
#                                 pass
#                         count += 1
#
#             # if item is just a string
#             elif re.search(r'\\\\', str(v)):
#                 try:
#                     detect[k] = detect[k].replace('\\\\', '\\')
#                 except:
#                     pass
#
#             elif re.search(r'\\?', str(v)) and not re.search(r'\\\?\\', str(v)):
#                 try:
#                     detect[k] = v.replace('\\?', '?')
#                 except:
#                     pass
#
#     else:
#         print("Error in Formatting: No dictionary found")
#         return False
#
#     return detect
