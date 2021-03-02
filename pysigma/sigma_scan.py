
import fnmatch
import re
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from pysigma.signatures import DetectionField, DetectionMap, Query


def match_search_id(signature, event, search_id):
    search_fields = signature.get_search_fields(search_id)
    if search_fields:
        return find_matches(event, search_fields)
    raise ValueError()


def check_pair(event, key, value: 'Query') -> bool:
    """
    Checks to see if a given key and value from the rule are also in the event.
    Takes into consideration any value modifiers.

    :param event: dict, a single event from the event log
    :param key: str, given dict key
    :param value: str, given key value
    :return: bool, whether or not the match exists in the event
    """
    # Before we can apply modifiers and search properly, we need to check if there
    # is even a value to modify, so do the null checks first
    if value is None:
        return event.get(key) is None
    if key not in event:
        return False

    if isinstance(value, re.Pattern):
        return bool(value.match(str(event[key])))
    else:
        # Because by default sigma string matching is case insensitive, lower the event
        # string before comparing it. The value string is already lowercase.
        # TODO potential optimization by caching lowercased event fields
        return str(event[key]).lower() == value


def find_matches(event: dict, search: 'DetectionField'):
    """
    Matches the items in the rule to the event. Iterates through the sections and if there's a list it iterates
    through that. Uses checkPair to see if the items in the list/dictionary match items in the event log.

    :param event: dict, event read from the Sysmon log
    :param search: An object describin what sort of search to run
    :return: bool, whether or not we found a match
    """
    if search.list_search:
        for field in search.list_search:
            for event_key in event:
                if check_pair(event, event_key, field):
                    return True
        return False

    for field in search.map_search:
        if find_matches_by_map(event, field):
            return True

    return False


def find_matches_by_map(event: dict, search: 'DetectionMap'):
    """

    :param event:
    :param search: a dict of fields to search. All must be satisfied.
    :return:
    """

    for field_name, (value, modifiers) in search.items():
        if not find_matches_by_map_entry(event, field_name, value, modifiers):
            return False
    return True


def find_matches_by_map_entry(event: dict, field_name, field_values: 'List[Query]', modifiers: List[str]):
    """
    :param event: the event to search in
    :param field_name: A field in the event we want to search
    :param field_values: valid values or patterns for the field in question
    :return:
    """

    # Normally any of the values in field_values is acceptable, but the all modifier inverts that
    if 'all' in modifiers:
        for permitted_value in field_values:
            if not check_pair(event, field_name, permitted_value):
                return False
        return True
    else:
        for permitted_value in field_values:
            if check_pair(event, field_name, permitted_value):
                return True
        return False


# def find_all_matches(event, rule_dict):
#     """
#     Matches the items in the rule to the event. Iterates through the sections and if there's a list it iterates
#     through that. Uses checkPair to see if the items in the list/dictionary match items in the event log.
#     Keeps track of number of both False and True matches.
#
#     :param event: dict, event read from the Sysmon log
#     :param rule_dict: dict, dictionary containing the rule info from Sigma .yml files.
#     :return: list, list of False/True matches
#     """
#
#     matches = []
#     if isinstance(rule_dict, dict):
#         for k, v in rule_dict.items():
#             if isinstance(v, list):
#                 for item in v:
#                     if not check_pair(event, k, item):
#                         matches.append(False)
#                     else:
#                         matches.append(True)
#
#             else:
#                 if not check_pair(event, k, v):
#                     matches.append(False)
#                 else:
#                     matches.append(True)
#
#     elif isinstance(rule_dict, list):
#             for item in rule_dict:
#                 if isinstance(item, dict):
#                     for ik, iv in item.items():
#                         if not check_pair(event, ik, iv):
#                             matches.append(False)
#                         else:
#                             matches.append(True)
#     return matches
#

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
            return False
        if search_misses >= permitted_misses:
            return True
    return False






