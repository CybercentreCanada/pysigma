import os
import yaml
import logging

logger = logging.getLogger('logfiles')
logger.setLevel('INFO')
rules_path = os.path.join('../neo-sigma-master/sigma-master/rules/windows')
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


def get_data(paths):
    rule_yaml_dicts = []
    for i in paths:
        # print(f'File {i}')
        with open(i) as y:
            data = y.read()
            try:
                yaml_dict = yaml.safe_load(data)
                rule_yaml_dicts.append(yaml_dict)
            except yaml.composer.ComposerError as e:
                failed_rules.append(i)
                print('Multiple Documents not supported ', i)
                # logger.error(e)
                continue
    return rule_yaml_dicts


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
    rule_yaml_dicts = get_data(paths)
    ctr_single, ctr_mult = 0,0
    for yaml in rule_yaml_dicts:
        keywords = []
        condition = get_condition(yaml)
        if isinstance(condition, list):
            # iterate through all conditions
            print('LOG', condition, yaml)
            pass
        elif isinstance(condition, str):
            words = condition.split()
            # goal here is to take words get the selections and each field and reconstruct the event log to create
            # an mvp match, start with one selection
            fields = simple_selection(words, yaml, ctr_single, ctr_mult)
            if not fields:
                continue


    print(frequencies)
    print('number rules', len(paths))


if __name__ == '__main__':
    main()
