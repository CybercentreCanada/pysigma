from . import signatures
from . import parser


class PySigma:  # what should I name it?
    def __init__(self):
        self.rules = {}
        self.callback = None

    def add_signature(self, signature_file):
        name, signature = signatures.loadSignature(signature_file)
        self.rules[name] = signature
        parser.rules = self.rules

    def check_event(self, event):
        alerts = parser.check_event(event, rules=self.rules)
        if self.callback:
            for a in alerts:
                self.callback(a, event)
        else:
            raise ValueError("There's no callback")
        pass

    def register_callback(self, c):
        self.callback = c

    @staticmethod
    def build_sysmon_events(logfile_path):
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

    def check_logfile(self, logfile_path):
        events = self.build_sysmon_events(logfile_path)
        for e in events:
            self.check_event(e)
