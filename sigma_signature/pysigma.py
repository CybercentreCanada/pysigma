from . import signatures
from . import parser
from yaml.composer import ComposerError
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

class PySigma:  # what should I name it?
    def __init__(self):
        self.rules = {}
        self.callback = None

    def add_signature(self, signature_file):
        name, signature = signatures.loadSignature(signature_file)
        detection = signature.get('detection')
        if not detection:
            raise ValueError("No detection key in signature")
        if 'near' in detection['condition']:
            raise ValueError("near-aggregation is not supported")
        self.rules[name] = signature
        parser.rules = self.rules

    def check_events(self, events):
        for event in events:
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
        return log_dict

    def check_logfile(self, logfile_path):
        events = self.build_sysmon_events(logfile_path)
        self.check_events(events)
