import os
from pysigma.exceptions import UnsupportedFeature
import logging
import pysigma.pysigma as s
logger = logging.getLogger('logfiles')
logger.setLevel('INFO')
rules_path = os.path.join('../neo-sigma-master/sigma-master/rules/windows/sysmon')
paths = []

remove_words = ['count', 'min', 'max', 'sum', '(', ')', '|', 'by', 'count()', '<', '>', 'near']
stop_words = ['and', 'or', 'not', 'OR', 'NOT', 'AND']
all_words = remove_words + stop_words + ['of', '1', 'all', 'them', '(1']
failed_rules = []
multiple_condition_rules = []


def get_rule_paths():
    for root, _, files in os.walk(rules_path):
        # print('root\n',root)
        if root != '.':
            # print('files\n',files)
            for file in files:
                # print('file')
                # print(os.path.join(root,file))
                if file.endswith('.yml'):
                    paths.append(os.path.join(root, file))
                # os.rmdir(file[:-4])
                # os.mkdir(os.path.join(root,file[:-4]))
    return paths


def add_rules(paths):
    sigma = s.PySigma()
    for i in paths:
        if i == '../neo-sigma-master/sigma-master/rules/windows/sysmon/sysmon_apt_turla_namedpipes.yml':
            with open(i) as y:
                data = y.read()
                try:
                    sigma.add_signature(data)
                except UnsupportedFeature as e:
                    #failed_rules.append(i)
                    print(e, i)
                    continue
    return sigma


def get_condition(yaml_dict):
    try:
        condition = yaml_dict['detection']['condition']
        tokens = condition.split()

    except AttributeError:
        logger.warning('multiple conditions not supported', yaml_dict['title'])
        multiple_condition_rules.append(condition)
    return condition


def clean_condition(condition):
    keywords = []
    for t in condition:
        if t not in stop_words:
            keywords.append(t)


def simple_selection(words, yaml, ctr_single, ctr_mult):
    if len(words) == 1:
        ctr_single = ctr_single  + 1
        selection = words[0]
        relevant_section = yaml['detection'][selection]
        print(selection, relevant_section)
        return relevant_section, ctr_single
    else:
        print('More than 1 word', words)
        return None, ctr_mult


def main():
    frequencies = {new_list: 0 for new_list in range(20)}
    paths = get_rule_paths()
    parser = add_rules(paths)
    ctr_single, ctr_mult = 0,0
    for sig_name, sig in parser.rules.items():
        print(sig_name)
        condition = sig.get_condition()
        generated_match_event = condition(sig)

    print(frequencies)
    print('number rules', len(paths))


if __name__ == '__main__':
    main()
