import typing
import logging

from yaml.composer import ComposerError

from . import signatures
from .exceptions import UnsupportedFeature
from . import parser
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
    def __init__(self):
        self.rules = {}
        self.callback = None

    def add_signature(self, signature_file: typing.Union[typing.IO, str]):
        signature = signatures.load_signature(signature_file)
        self.rules[signature.title] = signature
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

    def register_callback(self, c):
        self.callback = c

    @staticmethod
    def build_sysmon_events(logfile_path):
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

    def check_logfile(self, logfile_path):
        events = self.build_sysmon_events(logfile_path)
        self.check_events(events)
