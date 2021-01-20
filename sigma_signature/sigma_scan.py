
import fnmatch
import re
import base64

from .signatures import get_condition, get_data


def check_pair(event, key, value):
    """
    Checks to see if a given key and value from the rule are also in the event.
    Takes into consideration any value modifiers.

    :param event: dict, a single event from the event log
    :param key: str, given dict key
    :param value: str, given key value
    :return: bool, whether or not the match exists in the event
    """

    if '|' in key:
        modifiers = key.split('|')
        for word in modifiers:
            if word == '':
                modifiers.remove(word)
        key = modifiers[0]
        modifiers = modifiers[1:]
        #modifiers.remove(modifiers[0])

    else:
        modifiers = []

    if key in event:
        if len(modifiers) > 0:
            flag = False
            for word in modifiers:
                if word == 'contains':
                    if str(value) in str(event[key]):
                        flag = True
                    else:
                        flag = False
                elif word == 'all':
                    return None
                elif word == 'base64':
                    if str(event[key]) == str(base64.encodebytes(bytes(value))):
                        flag = True
                    else:
                        flag = False
                elif word == 'endswith':
                    if str(event[key]).endswith(str(value)):
                        flag = True
                    else:
                        flag = False
                elif word == 'startswith':
                    if str(event[key]).startswith(str(value)):
                        flag = True
                    else:
                        flag = False

            return flag

        elif '*' in str(value):
            return fnmatch.fnmatch(event[key], value)

        elif str(value) == '' or str(value) == 'null':
            try:
                return str(event[key]) == '' or str(event[key]) == 'None'
            except:
                return event[key] == '' or str(event[key]) == None

        else:
            try:
                return str(event[key]) == str(value)
            except:
                return event[key] == str(value)

    else:
        if str(value) == '' or str(value) == 'null':
            return True
        return False


def find_matches(event, rule_dict):
    """
    Matches the items in the rule to the event. Iterates through the sections and if there's a list it iterates
    through that. Uses checkPair to see if the items in the list/dictionary match items in the event log.

    :param event: dict, event read from the Sysmon log
    :param rule_dict: dict, dictionary containing the rule info from Sigma .yml files.
    :return: bool, whether or not we found a match
    """

    flag = False
    if isinstance(rule_dict, dict):
        for k, v in rule_dict.items():
            if isinstance(v, list):
                for item in v:
                    if not check_pair(event, k, item):
                        flag = False
                    else:
                        flag = True
                        break

                if not flag:
                    return False

            else:
                if not check_pair(event, k, v):
                    return False
                else:
                    flag = True

    elif isinstance(rule_dict, list):
            for item in rule_dict:
                if isinstance(item, dict):
                    for ik, iv in item.items():
                        if not check_pair(event, ik, iv):
                            flag = False
                        else:
                            flag = True
    return flag


def find_all_matches(event, rule_dict):
    """
    Matches the items in the rule to the event. Iterates through the sections and if there's a list it iterates
    through that. Uses checkPair to see if the items in the list/dictionary match items in the event log.
    Keeps track of number of both False and True matches.

    :param event: dict, event read from the Sysmon log
    :param rule_dict: dict, dictionary containing the rule info from Sigma .yml files.
    :return: list, list of False/True matches
    """

    matches = []
    if isinstance(rule_dict, dict):
        for k, v in rule_dict.items():
            if isinstance(v, list):
                for item in v:
                    if not check_pair(event, k, item):
                        matches.append(False)
                    else:
                        matches.append(True)

            else:
                if not check_pair(event, k, v):
                    matches.append(False)
                else:
                    matches.append(True)

    elif isinstance(rule_dict, list):
            for item in rule_dict:
                if isinstance(item, dict):
                    for ik, iv in item.items():
                        if not check_pair(event, ik, iv):
                            matches.append(False)
                        else:
                            matches.append(True)
    return matches


def analyze(event, rule_name, rule_dict):
    """
    Analyzes the truth value of each condition specified within the condition string of the rule.

    :param event: dict, event read from the Sysmon log
    :param rule_name: str, name of the rule
    :param rule_dict: dict, dictionary containing the rule info from Sigma .yml files.
    :return: dict, dictionary of truth values
    """

    condition = get_condition(rule_dict, rule_name)

    indicators = re.split('[(]|[)]| of |not| and | or |[|]', condition)
    for word in indicators:
        if word == '':
            indicators.remove(word)

    matches = {}

    for word in indicators:
        word = word.strip()
        if word in rule_dict['detection']:
            if find_matches(event, get_data(rule_dict, word)) and str(rule_name):
                matches[word] = True
            else:
                matches[word] = False

    return matches


def analyze_x_of(event, rule_name, rule_dict):
    """
    Analyzes the truth value of an 'x of' condition specified within the condition string of the rule.

    :param event: dict, event read from the Sysmon log
    :param rule_name: str, name of the rule
    :param rule_dict: dict, dictionary containing the rule info from Sigma .yml files
    :return: bool, truth value of 'x of' condition
    """

    condition = get_condition(rule_dict, rule_name)

    indicators = re.split('[(]|[)]| of |not| and | or |[|]', condition)
    valid_chars = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    for word in indicators:
        if indicators[0] == '':
            indicators.remove(indicators[0])
        elif word == '':
            indicators.remove(word)
        elif indicators[0].strip() not in valid_chars:
            if word != 'all':
                indicators.remove(word)
        if word == 'all' or indicators[0].strip() in valid_chars:
            break

    count = indicators[0].strip()
    search_id = indicators[1]

    matches = []

    if search_id.endswith('*'):

        search_id = search_id.strip('*')

        for word in rule_dict['detection']:
            if word.startswith(search_id):
                if find_matches(event, get_data(rule_dict, word)) and str(rule_name):
                    matches.append(True)
                else:
                    matches.append(False)

        if count == 'all':
            if False in matches:
                return False
            return True
        else:
            count = int(count)
            if matches.count(True) == count:
                return True
            return False

    elif search_id == 'them':

        for word in rule_dict['detection']:
            if word != 'condition':
                if find_matches(event, get_data(rule_dict, word)) and str(rule_name):
                    matches.append(True)
                    if count != 'all':
                        count = int(count)
                        if matches.count(True) == count:
                            return True
                else:
                    matches.append(False)
                    if count == 'all':
                        return False

        if count == 'all':
            return True
        return False

    else:

        matches = find_all_matches(event, get_data(rule_dict, search_id))

        if count == 'all':
            if False in matches:
                return False
            return True
        else:
            count = int(count)
            if matches.count(True) == count:
                return True
            return False






