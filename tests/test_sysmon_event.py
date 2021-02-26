"""
Find way to validate that events are hitting on the right rules
"""
import os
import os.path
import pytest
from pysigma import PySigma, parser, load_events


RULE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../rules'))
sample_rule = {'System File Execution Location Anomaly': {'detection': {'selection': {'Image': ['*\\svchost.exe', '*\\rundll32.exe', '*\\services.exe', '*\\powershell.exe', '*\\regsvr32.exe', '*\\spoolsv.exe', '*\\lsass.exe', '*\\smss.exe', '*\\csrss.exe', '*\\conhost.exe', '*\\wininit.exe', '*\\lsm.exe', '*\\winlogon.exe', '*\\explorer.exe', '*\\taskhost.exe', '*\\Taskmgr.exe', '*\\sihost.exe', '*\\RuntimeBroker.exe', '*\\smartscreen.exe', '*\\dllhost.exe', '*\\audiodg.exe', '*\\wlanext.exe']}, 'filter': {'Image': ['C:\\Windows\\System32\\\\*', 'C:\\Windows\\system32\\\\*', 'C:\\Windows\\SysWow64\\\\*', 'C:\\Windows\\SysWOW64\\\\*', 'C:\\Windows\\explorer.exe', 'C:\\Windows\\winsxs\\\\*', 'C:\\Windows\\WinSxS\\\\*', '\\SystemRoot\\System32\\\\*']}, 'condition': 'selection and not filter'}, 'description': 'Detects a Windows program executable started in a suspicious folder', 'level': 'high', 'tags': ['attack.defense_evasion', 'attack.t1036'], 'logsource': {'category': 'process_creation', 'product': 'windows'}}}
logfile_path = os.path.abspath(os.path.join(os.path.dirname(__file__), './xml_example'))


@pytest.fixture
def sigma_parser():
    sigma_parser = PySigma()
    sigma_parser = load_rule(sigma_parser)
    return sigma_parser


def load_rule(sigma_parser):
    rules = os.listdir(RULE_DIR)
    for rule in rules:
        with open(os.path.join(RULE_DIR, rule), 'r') as fp:
            sigma_parser.add_signature(fp)
    return sigma_parser


def test_init():
    # initialize pysigma
    sigma_parser = PySigma()
    assert sigma_parser.rules == {}
    assert sigma_parser.callback is None


# def test_add_signature(sigma_parser):
#     signatures = load_rule()
#     for signature_name, signature in signatures.items():
#         sigma_parser.add_signature(signature)
#     assert sample_rule.items() <= sigma_parser.rules.items()


def build_sysmon_events():
    log_dict = load_events(logfile_path)
    try:
        # handle single event
        if type(log_dict['Events']['Event']) is list:
            events = log_dict['Events']['Event']
        else:
            events = [log_dict['Events']['Event']]
    except KeyError:
        raise ValueError("The input file %s does not contain any events or is improperly formatted")
    return events


def check_events(self, events):
    for event in events:
        alerts = parser.check_event(event, rules=self.rules)
        if alerts:
            print('alerts ', alerts)


def test_check_logfile(sigma_parser):
    events = build_sysmon_events()
    alerts = sigma_parser.check_events(events)
    assert alerts
