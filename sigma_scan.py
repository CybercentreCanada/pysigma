from lark import Lark, Transformer, Token, Tree
from pathlib import Path
from signatures import *
from WindowsEventLogsHelper import *
import fnmatch


grammar = '''
        start: pipe_rule 
        
        %import common.WORD   // imports from terminal library
        %ignore " "           // Disregard spaces in text
        
        pipe_rule: or_rule ["|" aggregation_expression] -> pipe_rule
        or_rule: and_rule ("or" and_rule)* -> or_rule
        and_rule: not_rule ("and" not_rule)* -> and_rule
        not_rule: [NOT] atom -> not_rule
        atom: search_id | "(" pipe_rule ")" | x_of -> atom_rule
        search_id: /[a-zA-Z_][a-zA-Z0-9_]*/
        
        x: "all" | NUMBER
        x_of: x "of" search_id
            | "all of" search_id
            | "all of them"
            | x "of them"
        aggregation_expression: aggregation_function "(" [aggregation_field] ")" [ "by" group_field ] comparison_op value 
                              | near_aggregation
        aggregation_function: "count" | "min" | "max" | "avg" | "sum"
        near_aggregation: "near" or_rule
        aggregation_field: search_id
        group_field: search_id
        comparison_op: ">" | "<" | "="
        value: NUMBER
        NUMBER: /[1-9][0-9]*/
        NOT: "not"

        '''

SCRIPT_LOCATION = Path(__file__).resolve().parent
# Directory of all sysmon rules
test_rules = SCRIPT_LOCATION / Path("test_rules")
# List of all events
test_event = SCRIPT_LOCATION / Path("event.xml")

rules = loadSignatures(test_rules)
event = load_events(test_event)
event = prepareEventLog(event)


class LogicTransformer(Transformer):

    def identifier_rule(self, args):

        for r in rules:

            if int(event['EventID']) == 22:
                break

            # Call analyze on all rules in the rule directory to find matches for each event
            hits = analyze(event, str(r), rules[r])
            if args in hits:
                return hits[args]

    def atom_rule(self, args):
        if args.data == 'atom':
            if args.children[0].data == 'search_id':
                return self.identifier_rule(args.children[0].children[0].value)
            elif args[1] == '"(" pipe_rule ")"':
                return None
            elif args[1] == 'x_of':
                return None
        return None

    def not_rule(self, args):
        if args == True or args == False:
            return args
        elif args[0] == 'not':
            left = self.atom_rule(args[1])
            for right in args[1:]:
                left = not self.atom_rule(right)
            return left
        return self.atom_rule(args[0])

    def and_rule(self, args):
        if args == True or args == False:
            return args
        elif len(args) >= 2 and (args[0] == True or args[0] == False):
            left = args[0]
            for right in args[1:]:
                left = left and right
            return left
        elif args[0] == 'and_rule':
            left = self.not_rule(args[1])
            for right in args[1:]:
                left = left and self.not_rule(right)
            return left
        return self.not_rule(args[0])

    def or_rule(self, args):
        if args == True or args == False:
            return args
        elif len(args) >= 2 and (args[0] == True or args[0] == False):
            left = args[0]
            for right in args[1:]:
                left = left or right
            return left
        elif args[0] == 'or_rule':
            left = self.and_rule(args[1])
            for right in args[1:]:
                left = left or self.and_rule(right)
            return left
        return self.and_rule(args[0])

    def pipe_rule(self, args):
        if args == True or args == False:
            return args
        elif len(args) == 2 and (args[0] == True or args[0] == False):
            return args[0] and args[1]
        elif args[0] == 'not':
            left = self.or_rule(args[1])
            for right in args[1:]:
                left = left and self.or_rule(right)
            return left
        return self.or_rule(args[0])


def check_pair(event, key, value):
    """
    Checks to see if a given key and value from the rule are also in the event.
    :param event: dict, a single event from the event log
    :param key: str, given dict key
    :param value: str, given key value
    :return: bool,
    """

    if key in event:
        if '*' in str(value):
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


def analyze(event, rule_name, rule):

    condition = get_condition(rule, rule_name)
    print('Condition: ' + condition)

    indicators = re.split('[(]|[)]| all | of | them |not| and | or |[|]', condition)
    for word in indicators:
        if word == '':
            indicators.remove(word)

    print(indicators)

    matches = {}

    for word in indicators:
        word = word.strip()
        if word in rule['detection']:
            if find_matches(event, get_data(rule, word)) and str(rule_name):
                matches[word] = True
            else:
                matches[word] = False

    print(matches)
    return matches

