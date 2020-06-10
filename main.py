from sigma_scan import *

def main():

    for r in rules:
        condition = get_condition(rules[r], str(r))
        print(condition)
        parser = Lark(grammar, parser='lalr', transformer=LogicTransformer())
        print(parser.parse(condition).pretty())


main()
