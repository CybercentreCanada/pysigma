import os
import yaml
import logging
logger = logging.getLogger('logfiles')
logger.setLevel('INFO')
print(os.listdir())
rules_path = os.path.join('../neo-sigma-master/sigma-master/rules/windows')
paths = []
remove_words = ['count', 'min', 'max', 'sum', '(', ')', '|', 'by', 'count()',]
stop_words = ['and', 'or', 'not']
failed_rules = []
multiple_condition_rules = []

def get_rule_paths():
    for root, _, files in os.walk(rules_path):
        print('root\n',root)
        if root != '.':
            print('files\n',files)
            for file in files:
                print('file')
                print(os.path.join(root,file))
                if file.endswith('.yml'):
                    paths.append(os.path.join(root,file))
                #os.rmdir(file[:-4])
                #os.mkdir(os.path.join(root,file[:-4]))
    return paths


def get_data(paths):
    rule_yaml_dicts = []
    for i in paths:

        print(f'File {i}')
        with open(i) as y:
            data = y.read()
            try:
                yaml_dict = yaml.safe_load(data)
                rule_yaml_dicts.append(yaml_dict)
            except yaml.composer.ComposerError as e:
                failed_rules.append(i)
                print('failed rule ', i )
                logger.error(e)
                continue
    return rule_yaml_dicts

def get_condition(yaml_dict):
    try:
        condition = yaml_dict['detection']['condition']
        tokens = condition.split()

    except AttributeError:
        logger.error('multiple conditions not supported', condition)
        multiple_condition_rules.append(condition)
    return condition

def clean_condition(condition):
    keywords = []
    for t in condition:
        if t not in stop_words:
            keywords.append(t)

def simple_selection(condition, yaml):
    relevant_section = yaml['selection']
    return relevant_section

def main():
    paths = get_rule_paths()
    rule_yaml_dicts = get_data(paths)
    for yaml in rule_yaml_dicts:
        condition = get_condition(yaml)
        words = condition.split()
        print(words, len(words))
    print('number rules', len(paths))

if __name__ == '__main__':
    main()

