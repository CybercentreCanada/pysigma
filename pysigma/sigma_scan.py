
import fnmatch
import re
import base64


def match_search_id(signature, event, search_id):
    search_fields = signature.get_search_fields(search_id)
    if search_fields:
        return find_matches(event, search_fields)
    raise ValueError()


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
            if isinstance(value, list):
                flags = [fnmatch.fnmatch(event[key], pattern) for pattern in value]
                return True if True in flags else False
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


# def analyze_condition(event, rule_dict, condition, rule_name):
#     indicators = re.split('[(]|[)]| of |not| and | or |[|]', condition)
#     for word in indicators:
#         if word == '':
#             indicators.remove(word)
#     matches = {}
#
#     for word in indicators:
#         word = word.strip()
#         if word in rule_dict['detection']:
#             if find_matches(event, get_data(rule_dict, word)) and str(rule_name):
#                 matches[word] = True
#             else:
#                 matches[word] = False
#     return matches
#
#
# def analyze(event, rule_name, rule_dict):
#     """
#     Analyzes the truth value of each condition specified within the condition string of the rule.
#
#     :param event: dict, event read from the Sysmon log
#     :param rule_name: str, name of the rule
#     :param rule_dict: dict, dictionary containing the rule info from Sigma .yml files.
#     :return: dict, dictionary of truth values
#     """
#
#     condition = get_condition(rule_dict, rule_name)
#     if isinstance(condition, list):
#         list_matches = [analyze_condition(event, rule_dict, c, rule_name) for c in condition]
#         return list_matches
#
#     if isinstance(condition, str):
#         matches = analyze_condition(event, rule_dict, condition, rule_name)
#         return [matches]


def analyze_x_of(signature, event, count, selector):
    """
    Analyzes the truth value of an 'x of' condition specified within the condition string of the rule.

    :param signature: Signature currently being applied
    :param event: event currently being scanned
    :param count: left side of the x of statement, either 1 or None (for all)
    :param selector: right side of the x of statement, a pattern or None (for all)
    :return: bool, truth value of 'x of' condition
    """

    # First we need to choose our set of fields based on our selector.
    matches = {}
    all_searches = signature.get_all_searches()

    if selector is None:  # None indicates all.
        matches = all_searches
    else:
        for search_id, search_fields in all_searches.items():
            if fnmatch.fnmatch(search_id, selector):
                matches[search_id] = search_fields

    if count is None:
        count = len(matches)
    permitted_misses = len(matches) - count

    # Now that we have our searches to check, run them
    search_hits = 0
    search_misses = 0
    for search_id, search_fields in matches.items():
        if find_matches(event, search_fields):
            search_hits += 1
        else:
            search_misses += 1

        # Short circuit if we found the matches, or if we can't find the number anymore
        if search_hits <= count:
            return True
        if search_misses >= permitted_misses:
            return False
    return False






