from typing import Dict
from lark import Lark, Transformer
from pathlib import Path
from WindowsEventLogsHelper import load_events, prepareEventLog
from build_alert import callback_buildReport, Alert, check_timeframe
from sigma_scan import analyze_x_of, analyze
from signatures import loadSignatures, get_condition, get_description, get_level, get_yaml_name

SCRIPT_LOCATION = Path(__file__).resolve().parent

# Rules & events to be tested
test_rules = SCRIPT_LOCATION / Path("test_rules")
test_events = [SCRIPT_LOCATION / Path("test_a.xml")]

rules: Dict[str, Dict] = loadSignatures(test_rules)

event = None
rule = None
timed_events = {}

# Grammar defined for the condition strings within the Sysmon rules
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
    """
    Defines what each rule (as specified within the grammar) is meant to do, in order to determine the truth value of the
    condition string within each Sysmon .yml file.
    Works recursively.
    """

    def identifier_rule(self, args):
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


# Create & initialize Lark class instance
parser = Lark(grammar, parser='lalr', transformer=LogicTransformer())


def main():
    """
    Main function tests every event against every rule in the provided directory to generate a list of alerts
    (per event) for which rules have been hit on.
     
    """

    for e in test_events:
        global event
        event = load_events(e)
        event = prepareEventLog(event)

        alerts = []

        for rule_name, rule_obj in rules.items():
            global rule
            rule = rule_name
            condition = get_condition(rule_obj, rule_name)
            result = parser.parse(condition).pretty()

            if 'True' in result:
                if 'timeframe' in rule_obj['detection']:
                    check_timeframe(rule_obj, rule_name, timed_events, event, alerts)
                else:
                    callback_buildReport(alerts, Alert(rule_name, get_description(rule_obj), event, get_level(rule_obj), get_yaml_name(rule_obj)))

        print('\033[4mAlerts\033[0m')
        print('Event: ' + e.name)
        print(alerts)


main()
