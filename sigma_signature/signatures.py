import os
import yaml
import re


def loadSignatures(signatureDir):
    """
    Load all Sigma signatures from a directory

    :param signatureDir: Directory which contains all Sigma signature to load
    :return: A dictionary containing all loaded signatures
    """

    try:
        newdict = {}
        for files in os.listdir(signatureDir):
            dirfile = os.path.join(signatureDir, files)
            if os.path.isfile(dirfile):
                with open(dirfile, 'r') as yaml_in:
                    name, signature = loadSignature(yaml_in)
                    newdict[name] = signature
        return newdict

    except Exception as e:
        raise KeyError("Error in Formatting of Rules: Verify your YAML documents")

def loadSignature(signature_file):
    """
    Load a single sigma signature from a file object

    :param signature_file: a file like object containing sigma yaml
    :return: a tuple containing the name and a signature represented as a dictionary
    """
    yaml_data = yaml.safe_load_all(signature_file)
    for item in yaml_data:
        if isinstance(item, dict):
            subset_dict = {k: item[k] for k in ('detection', 'description', 'status', 'level', 'tags')}
            return (item['title'], subset_dict)



def escape_compatible(detect):
    """
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
