#Find way to validate that events are hitting on the right rules
import os
from sigma_signature import pysigma
from sigma_signature import parser

import json
import pytest
RULE_DIR = '../rules'
sample_rule = {'System File Execution Location Anomaly': {'detection': {'selection': {'Image': ['*\\svchost.exe', '*\\rundll32.exe', '*\\services.exe', '*\\powershell.exe', '*\\regsvr32.exe', '*\\spoolsv.exe', '*\\lsass.exe', '*\\smss.exe', '*\\csrss.exe', '*\\conhost.exe', '*\\wininit.exe', '*\\lsm.exe', '*\\winlogon.exe', '*\\explorer.exe', '*\\taskhost.exe', '*\\Taskmgr.exe', '*\\sihost.exe', '*\\RuntimeBroker.exe', '*\\smartscreen.exe', '*\\dllhost.exe', '*\\audiodg.exe', '*\\wlanext.exe']}, 'filter': {'Image': ['C:\\Windows\\System32\\\\*', 'C:\\Windows\\system32\\\\*', 'C:\\Windows\\SysWow64\\\\*', 'C:\\Windows\\SysWOW64\\\\*', 'C:\\Windows\\explorer.exe', 'C:\\Windows\\winsxs\\\\*', 'C:\\Windows\\WinSxS\\\\*', '\\SystemRoot\\System32\\\\*']}, 'condition': 'selection and not filter'}, 'description': 'Detects a Windows program executable started in a suspicious folder', 'level': 'high', 'tags': ['attack.defense_evasion', 'attack.t1036'], 'logsource': {'category': 'process_creation', 'product': 'windows'}}}
logfile_path = './xml_example'

#
# def sigma_hit(self, alert, event):
#     title = alert['title']
#     if title not in self.hits:
#         event['score'] = alert['score']
#         self.hits[title] = [event]
#     else:
#         self.hits[title].append(event)

def test_init():
    #initialize pysigma
    sigma_parser = pysigma.PySigma()
    # sigma_parser.register_callback(sigma_hit)
    assert sigma_parser.rules == {}
    assert sigma_parser.callback == None
    return sigma_parser

def load_rule():
    import yaml
    print('\nhello\n\n')
    print(os.listdir(RULE_DIR))
    rules = os.listdir(RULE_DIR)
    dict_rules = {}
    for rule in rules:
        with open(os.path.join('../rules', rule), 'r') as fp:
            content = fp.read()
            dict_rules[rule] = content
    return dict_rules

def test_add_signature(sigma_parser):
    signatures = load_rule()
    for signature_name, signature in signatures.items():
        sigma_parser.add_signature(signature)
    assert sample_rule.items() <= sigma_parser.rules.items()
    return sigma_parser


def build_sysmon_events():
    log_dict = parser.load_events(logfile_path)
    try:
        # handle single event
        if type(log_dict['Events']['Event']) is list:
            events = log_dict['Events']['Event']
        else:
            events = [log_dict['Events']['Event']]
    except KeyError:
        raise ValueError("The input file %s does not contain any events or is improperly formatted")
    return events
# def test_build_sysmon_events():
#     log_dict = parser.load_events(logfile_path)
#     assert log_dict == sample_event_dict


def check_events(self, events):
    forbidden_rules = ['RDP over Reverse SSH Tunnel WFP', 'Suspicious Execution from Outlook']
    for r in forbidden_rules:
        if r in self.rules:
            del self.rules[r]
    for event in events:
        alerts = parser.check_event(event, rules=self.rules)
        if alerts:
            print(alerts)



def test_check_logfile():
    events = build_sysmon_events()
    sigma_parser = pysigma.PySigma()
    sigma_parser = test_add_signature(sigma_parser)
    check_events(sigma_parser, events)
