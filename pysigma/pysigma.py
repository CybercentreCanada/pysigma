import argparse
import copy
import json
import logging
import os

from collections import defaultdict
from pathlib import Path
from typing import List, IO, Union, Dict
from yaml.composer import ComposerError

from . import signatures
from . import parser
from .validator_cli import get_sigma_paths_from_dir
from .windows_event_logs import load_events


logger = logging.getLogger('pysigma')
logger.setLevel(logging.INFO)


def val_file(filename):
    ps = PySigma()
    with open(filename) as fh:
        try:
            ps.add_signature(fh)
            return True
        except ValueError:
            return False
        except ComposerError:
            return False
        except KeyError as e:
            logger.error(filename)
            logger.error(e)
            return False


class PySigma:
    def __init__(self, rule_files = [], callback = None):
        self.rules = {}
        self.callback = callback or self.default_callback
        self.hits = {}

        for rule in rule_files:
            self.add_signature(open(rule, 'r').read())

    def add_signature(self, signature_file: Union[IO, str]):
        signature = signatures.load_signature(signature_file)
        self.rules[signature.id] = signature
        parser.rules = self.rules

    def check_events(self, events):
        all_alerts = []
        for event in events:
            alerts = parser.check_event(event, rules=self.rules)
            if self.callback:
                for a in alerts:
                    self.callback(a, event)
            all_alerts.extend(alerts)
        return all_alerts

    @staticmethod
    def build_sysmon_events(logfile_path):
        log_dict, log_type = load_events(logfile_path)
        try:
            # handle single event
            if log_type == 'xml':
                if type(log_dict['Events']['Event']) is list:
                    events = log_dict['Events']['Event']
                else:
                    events = [log_dict['Events']['Event']]
            elif log_type == 'evtx':
                events = log_dict
        except KeyError:
            raise ValueError("The input file %s does not contain any events or is improperly formatted")
        except TypeError:
            raise ValueError("The input file %s does not contain any events or is improperly formatted")
        return events

    def check_logfile(self, logfile_path):
        events = self.build_sysmon_events(logfile_path)
        self.check_events(events)
        return events

    def default_callback(self, alert: Dict, event: Dict) -> None:
        id = alert['id']
        copied_event = copy.deepcopy(event)
        if id not in self.hits:
            copied_event['score'] = alert['score']
            copied_event['signature_source'] = alert['signature_source']
            self.hits[id] = [copied_event]
        else:
            self.hits[id].append(copied_event)


arg_parser = argparse.ArgumentParser(description='Sigma Checker - used to test rules on samples')
arg_parser.add_argument('paths', nargs='+', type=str, default=[],
                    help='A list of files or folders to be analyzed.')
arg_parser.add_argument('-r', '--rules-dir', dest='rules_dir')


def parse_args(custom_args=None):
    if isinstance(custom_args, list):
        options = arg_parser.parse_args(custom_args)
    else:
        options = arg_parser.parse_args()

    return options

def check_with_rules(sample_list: List[str], rules_dir: str):
    # Instantiate class instance
    sigma_checker = PySigma(rule_files=get_sigma_paths_from_dir(Path(rules_dir), recursive=True))

    # Check imported rules against file(s)
    scoreboard = defaultdict(dict)
    for sample in sample_list:
        sigma_checker.check_logfile(sample)
        source_hits = defaultdict(list)
        for id, events in sigma_checker.hits.items():
            for event in events:
                if event.get('score'):
                    source_hits[event['score']].append(id)
        scoreboard[sample] = source_hits
    return scoreboard


def main():
    print('Sigma Rule Checker')
    options = parse_args()
    samples = []

    for path in options.paths:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                samples.extend([os.path.join(root, file) for file in files])
        else:
            samples.append(path)

    scoreboard = check_with_rules(samples, options.rules_dir)
    print(json.dumps(scoreboard, indent=4))



if __name__ == '__main__':
    main()
