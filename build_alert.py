
class alert:
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
