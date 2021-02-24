import os
from typing import Dict, List
import re

import yaml


class SignatureLoadError(KeyError):
    pass


class Detection:
    def __init__(self, data):
        self.detection = data['detection']
        self.logsource = data.get('logsource')


class Signature:
    def __init__(self, data: List[Dict]):
        self.title = None
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
        if not self.detections:
            raise SignatureLoadError('detection')


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
                    name, signature = load_signature(yaml_in)
                    newdict[name] = signature
        return newdict

    except Exception:
        raise KeyError("Error in Formatting of Rules: Verify your YAML documents")


def load_signature(signature_file) -> Signature:
    """
    Load a single sigma signature from a file object

    TODO introduce caching at this layer?

    :param signature_file: a file like object containing sigma yaml
    :return: Signature object
    """
    return Signature(list(yaml.safe_load_all(signature_file)))


def escape_compatible(detect):
    r"""
    Looks through a yaml signature detection section and replaces all escape characters with just the characters to be
    compatible ( i.e. \\ --> \ )

    :param detect: dict, detection section of the yaml signature
    :return: dict, fixed detection section
    """

    # check for dict
    if isinstance(detect, dict):
        # check all items in dict
        for k, v in detect.items():
            # check for dict
            if isinstance(v, dict):
                # check all items in dict
                for k1, v1 in v.items():
                    # check for list
                    if isinstance(v1, list):
                        count = 0
                        for item in v1:
                            if re.search(r'\\\\', str(item)):
                                try:
                                    detect[k][k1][count] = item.replace('\\\\', '\\')
                                except:
                                    pass

                            elif re.search(r'\\?', str(item)) and not re.search(r'\\\?\\', str(item)):
                                try:
                                    detect[k][k1][count] = item.replace('\\?', '?')
                                except:
                                    pass
                            count += 1

                    # if item is just a string
                    elif re.search(r'\\\\', str(v1)):
                        try:
                            detect[k][k1] = v1.replace('\\\\', '\\')
                        except:
                            pass

                    elif re.search(r'\\?', str(v1)) and not re.search(r'\\\?\\', str(v1)):
                        try:
                            detect[k][k1] = v1.replace('\\?', '?')
                        except:
                            pass

            # check for list
            elif isinstance(v, list):
                    count = 0
                    for item in v:
                        if re.search(r'\\\\', str(item)):
                            try:
                                detect[k][count] = item.replace('\\\\', '\\')
                            except:
                                pass

                        elif re.search(r'\\?', str(item)) and not re.search(r'\\\?\\', str(item)):
                            try:
                                detect[k][count] = item.replace('\\?', '?')
                            except:
                                pass
                        count += 1

            # if item is just a string
            elif re.search(r'\\\\', str(v)):
                try:
                    detect[k] = detect[k].replace('\\\\', '\\')
                except:
                    pass

            elif re.search(r'\\?', str(v)) and not re.search(r'\\\?\\', str(v)):
                try:
                    detect[k] = v.replace('\\?', '?')
                except:
                    pass

    else:
        print("Error in Formatting: No dictionary found")
        return False

    return detect


def get_yaml_name(rule_dict):
    """
    Gets file name of yaml rule that was hit on

    :param rule_dict: dict, our dictionary containing the rule info from Sigma .yml files.
    :return: str, filename of the rule
    """

    return rule_dict['yaml_name']


def get_description(rule_dict):
    """
    Gets the description of the rule for the result log.

    :param rule_dict: dict, our dictionary containing the rule info from Sigma .yml files.
    :return: str, description of the rule
    """

    return rule_dict['description']


def get_condition(rule_dict, condition):
    """
    Gets the condition string from the rule for the analyze function.

    :param rule_dict: dict, our dictionary containing the rule info from Sigma .yml files.
    :param condition: Condition we wish to analyze.
    :return: str, the condition for the rule, returned as a string.
    """

    try:
        return (rule_dict['detection']['condition']).lower()

    except KeyError:
        print("Error: No Condition Found: " + str(condition))
        return "none"
    except AttributeError:
        # If condition is a list
        return [condition.lower() for condition in rule_dict['detection']['condition']]


def get_data(rule_dict, key):
    """
    Pulls out the data from a specific section in detection.

    :param rule_dict: dict, our dictionary containing the rule info from Sigma .yml files.
    :param key: str, name of field we wish to extract info from within the detection field of the rule dict.
    :return dict: sub-dict of selected info from given field.
    """

    try:
        return rule_dict['detection'][str(key)]

    except KeyError:
        print("Error: No Data Found: " + str(key))
        return "none"


def get_level(rule_dict):
    """
    Gets the level of the rule.

    :param rule_dict: dict, our dictionary containing the rule info from Sigma .yml files.
    :return: str, level of the rule
    """

    return rule_dict['level']
