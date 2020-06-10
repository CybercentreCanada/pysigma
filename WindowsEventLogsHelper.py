from xml.parsers.expat import ExpatError
from io import open

import collections
import xmltodict


def load_events(xmlLogs):
    """
    Opens sysmon xml logs as a readable file, and turns the events into dicts
    :param xmlLogs:
    :return:
    """
    try:
        with open(xmlLogs, "r", encoding='utf-8', errors='ignore') as fp:
            return xmltodict.parse(fp.read())
    except ExpatError:
        raise KeyError("Error: Format error in the Event log file")


def flattened(event):
    """
    Unnest event logs with moving all items at the first level
    :param event: event
    :return: flattened event
    """

    items = []
    for key, value in event.items():
        if isinstance(value, collections.MutableMapping):
            items.extend(flattened(value).items())
        else:
            items.append((key, value))
    return dict(items)


def convertEventDataToKeyValue(event_dict):
    """
    Convert event's data to as key value pair
    "@Name": "UtcTime", "#text": "2018-08-21 03:09:31.314" to UtcTime: 2018-08-21 03:09:31.314
    :param event_dict: event
    :return: k,v Data section
    """

    tempdict = {}
    data = event_dict['Data']
    event_dict.update({'StartModule': None})

    for item in data:
        key = 0
        value = 0
        for k, v in item.items():
            if k == '#text':
                value = v
            elif k == '@Name':
                key = v
            else:
                print("Error in Data Section: Formatting")
                break
            if (key != 0) and (value != 0):
                tempdict.update({key: value})

    del event_dict['Data']

    for k, v in tempdict.items():
        event_dict.update({k: v})
    return event_dict


def prepareEventLog(event):
    """
    Prepares event log for use and info extraction. Flattens event log, and converts event
    to key value pair.
    :param event: single sysmon event from log
    :return: dict, event dict
    """
    
    flat = flattened(event)
    return convertEventDataToKeyValue(flat)
