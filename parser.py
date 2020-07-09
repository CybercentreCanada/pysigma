from typing import Dict
from lark import Lark, Transformer
from pathlib import Path
from WindowsEventLogsHelper import *
from sigma_scan import *
from build_alert import *
from datetime import datetime

SCRIPT_LOCATION = Path(__file__).resolve().parent
# Directory of all sysmon rules
test_rules = SCRIPT_LOCATION / Path("test_rules")
test_event = [SCRIPT_LOCATION / Path("dllload1.xml"), SCRIPT_LOCATION / Path("dllload2.xml")]

rules: Dict[str, Dict] = loadSignatures(test_rules)

event = None
rule = None
timed_events = {}

grammar = '''
        start: pipe_rule 

        %import common.WORD   // imports from terminal library
        %ignore " "           // Disregard spaces in text

        pipe_rule: or_rule ["|" aggregation_expression] -> pipe_rule
        or_rule: and_rule ("or" and_rule)* -> or_rule
        and_rule: not_rule ("and" not_rule)* -> and_rule
        not_rule: [NOT] atom -> not_rule
        atom: search_id | "(" pipe_rule ")" | x_of -> atom_rule
        search_id: /[a-zA-Z_][a-zA-Z0-9*_]*/

        x: "all" | NUMBER
        x_of: x "of" search_id
            | x "of them" -> x_of_rule

        aggregation_expression: or_rule
                              | aggregation_function "(" [aggregation_field] ")" [ "by" group_field ] comparison_op value 
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


class LogicTransformer(Transformer):

    def identifier_rule(self, args):

        #if int(event['EventID']) == 22:
         #   break

        # Call analyze on all rules in the rule directory to find matches for each event
        hits = analyze(event, str(rule), rules[rule])
        if args in hits:
            return hits[args]

    def atom_rule(self, args):
        if isinstance(args, list):
            if args[0] == True or args[0] == False:
                return args[0]
            elif args[0].data == 'x_of':
                return self.x_of_rule(args[0].children)
        elif args == True or args == False:
            return args
        elif args.data == 'atom':
            if args.children[0] == True or args.children[0] == False:
                return args.children[0]
            elif args.children[0].data == 'search_id':
                return self.identifier_rule(args.children[0].children[0].value)
            elif args.children[0].data == 'x_of':
                return self.x_of_rule(args.children[0].children[0].value)
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

    def x_of_rule(self, args):
        if args[0] == True or args[0] == False:
            return args[0]
        elif args[0].data == 'x':
            return analyze_x_of(event, str(rule), rules[rule])
        return None


parser = Lark(grammar, parser='lalr', transformer=LogicTransformer())


def main():

    for e in test_event:
        global event
        event = load_events(e)
        event = prepareEventLog(event)

        alerts = []
   # timed_events = {}

        for rule_name, rule_obj in rules.items():
            global rule
            rule = rule_name
            condition = get_condition(rule_obj, rule_name)
            print('Condition: ' + condition)
            result = parser.parse(condition).pretty()
            print(result)

            if 'True' in result:
                if 'timeframe' in rule_obj['detection']:
                    timeframe = rule_obj['detection']['timeframe']

                    # time_limit = default_time_limit
                    if timeframe.endswith('M'):
                        time_limit = int(timeframe.strip('M')) * 30
                    elif timeframe.endswith('d'):
                        time_limit = int(timeframe.strip('d'))
                    elif timeframe.endswith('h'):
                        time_limit = int(timeframe.strip('h')) * 3600
                    elif timeframe.endswith('m'):
                        time_limit = int(timeframe.strip('m')) * 60
                    elif timeframe.endswith('s'):
                        time_limit = int(timeframe.strip('s'))
                    else:
                        raise ValueError(timeframe)

                    if rule_name in timed_events:
                        time = datetime.strptime(event['UtcTime'], '%Y-%m-%d %H:%M:%S.%f')
                        timed_events[rule_name].append(time)
                        event1 = timed_events[rule_name][0]
                        event2 = timed_events[rule_name][1]

                        if 'M' in timeframe or 'd' in timeframe:
                            time_taken = abs((event1 - event2).days)
                        else:
                            time_taken = abs((event1 - event2).total_seconds())

                        if 0 <= time_taken <= time_limit:
                            callback_buildReport(alerts, alert(rule_name, get_description(rule_obj), event, get_level(rule_obj), get_yaml_name(rule_obj)))
                            del timed_events[rule_name]

                        else:
                            del timed_events[rule_name]

                    else:
                        time = datetime.strptime(event['UtcTime'], '%Y-%m-%d %H:%M:%S.%f')
                        timed_events[rule_name] = [time]
                else:
                    callback_buildReport(alerts, alert(rule_name, get_description(rule_obj), event, get_level(rule_obj), get_yaml_name(rule_obj)))

        print('\033[4mAlerts\033[0m')
        print(alerts)


main()
