
import fnmatch
import re
import base64

from codecs import encode
from signatures import get_condition, get_data


def check_pair(event, key, value):
    """
    Checks to see if a given key and value from the rule are also in the event.
    :param event: dict, a single event from the event log
    :param key: str, given dict key
    :param value: str, given key value
    :return: bool,
    """

    if '|' in key:
        modifiers = re.split('[|]', key)
        for word in modifiers:
            if word == '':
                modifiers.remove(word)
        key = modifiers[0]
        modifiers.remove(modifiers[0])

    else:
        modifiers = []

    if key in event:
        if len(modifiers) > 0:
            flag = False
            for word in modifiers:
                if word == 'contains':
                    if value in str(event[key]):
                        flag = True
                elif word == 'all':
                    return None
                elif word == 'base64':
                    if str(event[key]) == str(base64.encodebytes(value)):
                        flag = True
                elif word == 'base64offset':
                    return None
                elif word == 'endswith':
                    if str(event[key]).endswith(value):
                        flag = True
                elif word == 'startswith':
                    if str(event[key]).startswith(value):
                        flag = True
                elif word == 'utf16le' or word == 'wide':
                    if str(event[key]) == str(encode(value, encoding='utf-16le')):
                        flag = True
                elif word == 'utf16be':
                    if str(event[key]) == str(encode(value, encoding='utf-16be')):
                        flag = True
                elif word == 'utf16':
                    if str(event[key]) == str(encode(value, encoding='utf-16')):
                        flag = True
            return flag

        elif '*' in str(value):
            return fnmatch.fnmatch(event[key], value)

        else:
            try:
                return str(event[key]) == str(value)
            except:
                return event[key] == str(value)

    else:
        return False


def find_matches(event, rule):
    """
    matches the items in the rule to the event... iterates through the sections and if there's a list it iterates
    through that. Uses checkPair to see if the items in the list/dictionary match items in the event log.
    :param event: dict, event read from the sysmon log
    :param rule: dict, dictionary of rules
    :return: bool, whether or not we found a match
    """

    flag = False
    if isinstance(rule, dict):
        for k, v in rule.items():
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

    elif isinstance(rule, list):
            for item in rule:
                if isinstance(item, dict):
                    for ik, iv in item.items():
                        if not check_pair(event, ik, iv):
                            flag = False
                        else:
                            flag = True
    return flag


def find_all_matches(event, rule):
    """
    matches the items in the rule to the event... iterates through the sections and if there's a list it iterates
    through that. Uses checkPair to see if the items in the list/dictionary match items in the event log.
    :param event: dict, event read from the sysmon log
    :param rule: dict, dictionary of rules
    :return: bool, whether or not we found a match
    """

    matches = []
    if isinstance(rule, dict):
        for k, v in rule.items():
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

    elif isinstance(rule, list):
            for item in rule:
                if isinstance(item, dict):
                    for ik, iv in item.items():
                        if not check_pair(event, ik, iv):
                            matches.append(False)
                        else:
                            matches.append(True)
    return matches


def analyze(event, rule_name, rule):

    condition = get_condition(rule, rule_name)
    #print('Condition: ' + condition)

    indicators = re.split('[(]|[)]| of |not| and | or |[|]', condition)
    for word in indicators:
        if word == '':
            indicators.remove(word)

    #print(indicators)

    matches = {}

    for word in indicators:
        word = word.strip()
        if word in rule['detection']:
            if find_matches(event, get_data(rule, word)) and str(rule_name):
                matches[word] = True
            else:
                matches[word] = False

    #print(matches)
    return matches


def analyze_x_of(event, rule_name, rule):

    condition = get_condition(rule, rule_name)
    #print('Condition: ' + condition)

    indicators = re.split('[(]|[)]| of |not| and | or |[|]', condition)
    valid_chars = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    for word in indicators:
        if word == '':
            indicators.remove(word)
        elif indicators[0] not in valid_chars:
            if word != 'all':
                indicators.remove(word)
        if word == 'all' or indicators[0] in valid_chars:
            break

    #print(indicators)

    count = indicators[0]
    search_id = indicators[1]

    matches = []

    if search_id.endswith('*'):

        search_id = search_id.strip('*')

        for word in rule['detection']:
            if word.startswith(search_id):
                if find_matches(event, get_data(rule, word)) and str(rule_name):
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

        for word in rule['detection']:
            if word != 'condition':
                if find_matches(event, get_data(rule, word)) and str(rule_name):
                    matches.append(True)
                    if count != 'all':
                        count = int(count)
                        if matches.count(True) == count:
                            return True
                else:
                    matches.append(False)
                    if count == 'all':
                        return False

        #print(matches)

        if count == 'all':
            return True
        return False

    else:

        matches = find_all_matches(event, get_data(rule, search_id))

        #print(matches)

        if count == 'all':
            if False in matches:
                return False
            return True
        else:
            count = int(count)
            if matches.count(True) == count:
                return True
            return False






