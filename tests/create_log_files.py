import os
from pysigma.exceptions import UnsupportedFeature
import logging
import pysigma.pysigma as s
import xmltodict
logger = logging.getLogger('logfiles')
logger.setLevel('INFO')
rules_path = os.path.join('../neo-sigma-master/sigma-master/rules/windows/sysmon')
paths = []




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
# def get_condition(yaml_dict):
#     try:
#         condition = yaml_dict['detection']['condition']
#         tokens = condition.split()
#
#     except AttributeError:
#         logger.warning('multiple conditions not supported', yaml_dict['title'])
#         multiple_condition_rules.append(condition)
#     return condition

def get_example_xml(flat_events):
    eventid = flat_events['EventID']
    with open("./eventid" + eventid) as fp:
        data = fp.read()
    return data

def modify_xml(flat_events, example_xml):

    converted_xml = xmltodict.parse(example_xml)
    modified_xml = converted_xml
    # assume all values are in EventData section
    data_names = converted_xml['Event']['EventData']['Data']
    for index, field in enumerate(data_names):
        name = field['@Name']
        if name in flat_events:
            modified_xml['Event']['EventData']['Data'][index]['#text'] = flat_events[name]

    return xmltodict.unparse(modified_xml)

def main():
    frequencies = {new_list: 0 for new_list in range(20)}
    paths = get_rule_paths()
    parser = add_rules(paths)
    for sig_name, sig in parser.rules.items():
        print(sig_name)
        condition = sig.get_condition()
        generated_flat_event = condition(sig)
        example_xml = get_example_xml(generated_flat_event)
        modified_xml = modify_xml(generated_flat_event, example_xml)
        print(modified_xml)

    print('number rules', len(paths))


if __name__ == '__main__':
    main()
