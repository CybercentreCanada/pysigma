import os
import typing
from typing import Dict, List
import re

import yaml

from .exceptions import UnsupportedFeature
from .parser import prepare_condition


class SignatureLoadError(KeyError):
    pass


class Detection:
    def __init__(self, data):
        self.detection = data['detection']
        self.logsource = data.get('logsource')
        self.timeframe = self.detection.pop('timeframe', None)

        self.condition = None
        if 'condition' in self.detection:
            self.condition = prepare_condition(self.detection.pop('condition'))


class Signature:
    def __init__(self, data: List[Dict], file_name: str):
        self.title = None
        self.file_name = file_name
        self.description = None
        self.level = None
        self.tags = None
        self.detections = []

        for segment in data:
            if 'title' in segment:
                self.title = segment['title']
            if 'description' in segment:
                self.description = segment['description']
            if 'level' in segment:
                self.level = segment['level']
            if 'tags' in segment:
                self.tags = segment['tags']
            if 'detection' in segment:
                self.detections.append(Detection(segment))

        if self.title is None:
            raise SignatureLoadError('title')
        if len(self.detections) == 0:
            raise SignatureLoadError('detection')
        if len(self.detections) > 1:
            raise UnsupportedFeature()

    def get_condition(self):
        return self.detections[0].condition

    def get_all_searches(self):
        return dict(self.detections[0].detection)

    def get_search_fields(self, search_id):
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


def load_signature(signature_file: typing.IO) -> Signature:
    """
    Load a single sigma signature from a file object

    TODO introduce caching at this layer?

    :param signature_file: a file like object containing sigma yaml
    :return: Signature object
    """
    return Signature(list(yaml.safe_load_all(signature_file)), file_name=signature_file.name)


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
