import os
from pysigma.exceptions import UnsupportedFeature
from collections import OrderedDict
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
        with open(i) as y:
            try:
                sigma.add_signature(y)
            except UnsupportedFeature as e:
                #failed_rules.append(i)
                print(e, i)
                continue
    return sigma

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
            flat_events.pop(name)
        try:
            modified_xml['Event']['EventData']['Data'][index]['#text'] = flat_events[name]
        except KeyError as e:
            pass
            #print('error', e)
    # add events that weren't already in xml, exclude eventid
    if len(flat_events) != 1:
        flat_events.pop('EventID')
        for event in flat_events:
            event_ordered_dict = OrderedDict([('@Name', event),
                                              ('#text',flat_events[event]),
                                              ])

            modified_xml['Event']['EventData']['Data'].append(event_ordered_dict)


    return xmltodict.unparse(modified_xml)
def create_xml_file(sig_name, xml_str):
    xml_str = xml_str.split('\n')[1]
    full_xml = "<Events> " + xml_str + "</Events>"
    print(full_xml)
    with open('./sysmon/'+sig_name, 'w') as fp:
        fp.write(full_xml)

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
        file_name = sig.file_name.split('/')[-1][:-3] + "xml"
        create_xml_file(file_name, modified_xml)

    print('number rules', len(paths))
    print(os.getcwd())


if __name__ == '__main__':
    main()
