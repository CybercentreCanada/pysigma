from typing import Dict, Callable
from lark import Lark, Transformer
from pathlib import Path
from .WindowsEventLogsHelper import load_events, prepareEventLog
from .build_alert import callback_buildReport, Alert, check_timeframe
from .exceptions import UnsupportedFeature
from .sigma_scan import analyze, analyze_x_of, match_search_id

SCRIPT_LOCATION = Path(__file__).resolve().parent

# Rules & events to be tested
# test_rules = SCRIPT_LOCATION / Path("rules")
# event_logfiles = []
# rules: Dict[str, Dict] = {}
# event = None
# rule = None
# timed_events = {}


# Grammar defined for the condition strings within the Sigma rules
grammar = '''
        start: pipe_rule 
        %import common.WORD   // imports from terminal library
        %ignore " "           // Disregard spaces in text
        pipe_rule: or_rule ["|" aggregation_expression] 
        or_rule: and_rule (("or"|"OR") and_rule)* 
        and_rule: not_rule (("and"|"AND") not_rule)* 
        not_rule: [not] atom 
        not: "NOT" | "not"
        atom: x_of | search_id | "(" pipe_rule ")"
        search_id: SEARCH_ID 
        x: ALL | NUMBER
        x_of: x OF (THEM | search_pattern)
        search_pattern: /[a-zA-Z_][a-zA-Z0-9*_]*/
        aggregation_expression: aggregation_function "(" [aggregation_field] ")" [ "by" group_field ] comparison_op value 
                              | near_aggregation
        aggregation_function: COUNT | MIN | MAX | AVG | SUM
        near_aggregation: "near" or_rule
        aggregation_field: SEARCH_ID
        group_field: SEARCH_ID
        comparison_op: GT | LT | EQ
        GT: ">" 
        LT: "<"
        EQ: "="
        value: NUMBER
        NUMBER: /[1-9][0-9]*/
        NOT: "NOT"
        SEARCH_ID: /[a-zA-Z_][a-zA-Z0-9_]*/
        ALL: "all"
        OF: "of"
        THEM: "them"
        COUNT: "count"
        MIN: "min"
        MAX: "max"
        AVG: "avg"
        SUM: "sum"
        '''


# class LogicTransformer(Transformer):
#     """
#     Defines what each rule (as specified within the grammar) is meant to do, in order to determine the truth value of the
#     condition string within each Sigma .yml file.
#     Works recursively.
#     """
#
#     def identifier_rule(self, args):
#         # Call analyze on all rules in the rule directory to find matches for each event
#         hits = analyze(event, str(rule), rules[rule])
#         if args in hits:
#             return hits[args]
#
#     def atom_rule(self, args):
#         if isinstance(args, list):
#             if args[0] == True or args[0] == False:
#                 return args[0]
#             elif args[0].data == 'x_of':
#                 return self.x_of_rule(args[0].children)
#         elif args == True or args == False:
#             return args
#         elif args.data == 'atom':
#             if args.children[0] == True or args.children[0] == False:
#                 return args.children[0]
#             elif args.children[0].data == 'search_id':
#                 return self.identifier_rule(args.children[0].children[0].value)
#             elif args.children[0].data == 'x_of':
#                 return self.x_of_rule(args.children[0].children[0].value)
#         return None
#
#     def not_rule(self, args):
#         if args == True or args == False:
#             return args
#         elif args[0] == 'not':
#             left = self.atom_rule(args[1])
#             for right in args[1:]:
#                 left = not self.atom_rule(right)
#             return left
#         return self.atom_rule(args[0])
#
#     def and_rule(self, args):
#         if args == True or args == False:
#             return args
#         elif len(args) >= 2 and (args[0] == True or args[0] == False):
#             left = args[0]
#             for right in args[1:]:
#                 left = left and right
#             return left
#         elif args[0] == 'and_rule':
#             left = self.not_rule(args[1])
#             for right in args[1:]:
#                 left = left and self.not_rule(right)
#             return left
#         return self.not_rule(args[0])
#
#     def or_rule(self, args):
#         if args == True or args == False:
#             return args
#         elif len(args) >= 2 and (args[0] == True or args[0] == False):
#             left = args[0]
#             for right in args[1:]:
#                 left = left or right
#             return left
#         elif args[0] == 'or_rule':
#             left = self.and_rule(args[1])
#             for right in args[1:]:
#                 left = left or self.and_rule(right)
#             return left
#         return self.and_rule(args[0])
#
#     def pipe_rule(self, args):
#         if args == True or args == False:
#             return args
#         elif len(args) == 2 and (args[0] == True or args[0] == False):
#             return args[0] and args[1]
#         elif args[0] == 'not':
#             left = self.or_rule(args[1])
#             for right in args[1:]:
#                 left = left and self.or_rule(right)
#             return left
#         return self.or_rule(args[0])
#
#     def x_of_rule(self, args):
#         if args[0] == True or args[0] == False:
#             return args[0]
#         elif args[0].data == 'x':
#             return analyze_x_of(event, str(rule), rules[rule])
#         return None
#
#
# # Create & initialize Lark class instance
# parser = Lark(grammar, parser='lalr', keep_all_tokens=True)
#

def check_event(raw_event, rules):
    event = prepareEventLog(raw_event)
    alerts = []

    for rule_name, rule_obj in rules.items():
        condition = rule_obj.get_condition()

        if condition(rule_obj, event):
            timeframe = rule_obj.get_timeframe()
            if timeframe is not None:
                check_timeframe(rule_obj, rule_name, timed_events, event, alerts)
            else:
                alert = Alert(rule_name, rule_obj.description, event, rule_obj.level,
                              rule_obj.file_name)
                callback_buildReport(alerts, alert)
    return alerts

#
# def parse_logfiles(*logfiles):
#     """
#     Main function tests every event against every rule in the provided list of files
#     :param logfiles: paths to each logfile
#     :return: dict of filename <-> event-alert tuples
#     """
#     for evt in logfiles:
#         event_logfiles.append(SCRIPT_LOCATION / Path(evt))
#     print()
#
#     file_event_alerts = {}
#
#     for f in event_logfiles:
#         log_dict = load_events(f)
#         try:
#             # handle single event
#             if type(log_dict['Events']['Event']) is list:
#                 events = log_dict['Events']['Event']
#             else:
#                 events = [log_dict['Events']['Event']]
#         except KeyError:
#             raise ValueError("The input file %s does not contain any events or is improperly formatted")
#
#         file_event_alerts[f.name] = []
#
#         for e in events:
#             alerts = check_event(e)
#             if len(alerts) > 0:
#                 file_event_alerts[f.name].append((e, alerts))
#
#     return file_event_alerts


def true_function(*state):
    return True


def false_function(*state):
    return False


class FactoryTransformer(Transformer):
    def start(self, args):
        return args[0]

    @staticmethod
    def search_id(args):
        name = args[0].value

        def match_hits(signature, event):
            return match_search_id(signature, event, name)

        return match_hits

    @staticmethod
    def search_pattern(args):
        return args[0].value

    def atom(self, args):
        if not all((callable(_x) for _x in args)):
            raise ValueError(args)
        return args[0]

    def not_rule(self, args):
        negate, value = args
        assert callable(value)
        if negate is None:
            return value

        def _negate(*state):
            return not value(*state)
        return _negate

    def and_rule(self, args):
        if not all((callable(_x) for _x in args)):
            raise ValueError(args)

        if len(args) == 1:
            return args[0]

        def _and_operation(*state):
            for component in args:
                if not component(*state):
                    return False
            return True

        return _and_operation

    def or_rule(self, args):
        if not all((callable(_x) for _x in args)):
            raise ValueError(args)

        if len(args) == 1:
            return args[0]

        def _or_operation(*state):
            for component in args:
                if component(*state):
                    return True
            return False

        return _or_operation

    def pipe_rule(self, args):
        value, aggregation = args
        assert callable(value)
        if aggregation is None:
            return value

        def _run_pipe(hits):
            raise NotImplementedError()
        return _run_pipe

    def x_of(self, args):
        print(args)
        target = None
        if args[0].children[0].type == 'NUMBER':
            target = int(args[0].children[0].value)

        selector = None
        if isinstance(args[2], str):
            selector = args[2]
        elif args[2].type == 'THEM':
            pass
        else:
            raise ValueError()

        # If its not "them" we need to use the value on the right side as a
        # search-id or pattern to select the detection sections to match
        def _check_of_sections(hits):
            return apply_x_of(hits, target, selector)
        return _check_of_sections

    def aggregation_expression(self, args):
        raise UnsupportedFeature("Aggregation expressions not supported.")

    def near_aggregation(self, args):
        raise UnsupportedFeature("Near operation not supported.")


# Create & initialize Lark class instance
factory_parser = Lark(grammar, parser='lalr', transformer=FactoryTransformer(), maybe_placeholders=True)


def prepare_condition(raw_condition):
    if isinstance(raw_condition, list):
        raw_condition = '(' + ') or ('.join(raw_condition) + ')'
    return factory_parser.parse(raw_condition)
