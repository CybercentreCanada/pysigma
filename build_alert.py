from datetime import datetime
from signatures import get_description, get_yaml_name, get_level


class Alert:
    """
    Alert log object used to store information on events that have matched up with yaml rules.
    Stores the rule title, filename, and description, event dict, and the rule level for scoring.
    """

    def __init__(self, title, description, event, level, yaml_name):
        self.title = title
        self.description = description
        self.event = event
        self.level = level
        self.yaml_name = yaml_name


def callback_buildReport(alert_list, alert):
    """
    Creates result entry with alert object, and provides a score relative to the rule level
    :param context: list, list of indicator names which have been hit on
    :param alert: alert_obj, contains rule title, description, level, and the event
    """

    if alert.level == 'low':
        score = 'low'

    elif alert.level == 'medium':
        score = 'medium'

    elif alert.level == 'high':
        score = 'high'

    elif alert.level == 'critical':
        score = 'critical'

    else:
        score = 'null'

    alertItem = {alert.title: score}
    alert_list.append(alertItem)


def check_timeframe(rule_obj, rule_name, timed_events, event, alerts):

    timeframe = rule_obj['detection']['timeframe']

    if timeframe.endswith('M'):
        time_limit = int(timeframe.strip('M')) * 30
    elif timeframe.endswith('d'):
        time_limit = int(timeframe.strip('d'))
    elif timeframe.endswith('h'):
        time_limit = int(timeframe.strip('h')) * 3600
    elif timeframe.endswith('m'):
        time_limit = int(timeframe.strip('m')) * 60
    elif timeframe.endswith('s'):
        time_limit = int(timeframe.strip('s'))
    else:
        raise ValueError(timeframe)

    if rule_name in timed_events:
        time = datetime.strptime(event['UtcTime'], '%Y-%m-%d %H:%M:%S.%f')
        timed_events[rule_name].append(time)
        event1 = timed_events[rule_name][0]
        event2 = timed_events[rule_name][1]

        if 'M' in timeframe or 'd' in timeframe:
            time_taken = abs((event1 - event2).days)
        else:
            time_taken = abs((event1 - event2).total_seconds())

        if 0 <= time_taken <= time_limit:
            callback_buildReport(alerts, Alert(rule_name, get_description(rule_obj), event, get_level(rule_obj),
                                               get_yaml_name(rule_obj)))
            del timed_events[rule_name]

        else:
            del timed_events[rule_name]

    else:
        time = datetime.strptime(event['UtcTime'], '%Y-%m-%d %H:%M:%S.%f')
        timed_events[rule_name] = [time]
