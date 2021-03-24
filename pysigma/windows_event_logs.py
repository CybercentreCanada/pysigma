from xml.parsers.expat import ExpatError
from io import open
from evtx import PyEvtxParser

import json
import collections
import xmltodict


def load_events(log_file_name):
    """
    Opens Sysmon logs as a readable file, and turns the events into dictionaries
    :param log_file_name: Sysmon evtx or xml log to be opened
    :return: dict of the Sysmon event log
    """
    try:
        with open(log_file_name, "r", encoding='utf-8', errors='ignore') as fp:
            magic = fp.read(7)
            fp.seek(0)
            if magic == 'ElfFile':
                # log is evtx type
                parser = PyEvtxParser(log_file_name)
                dictrecords = [json.loads(rec['data']) for rec in parser.records_json()]
                return dictrecords, 'evtx'
            elif magic == '<Events':
                return xmltodict.parse(fp.read()), 'xml'
            else:
                raise Exception('Invalid File magic')

    except ExpatError:
        raise KeyError("Error: Format error in the Event log file")


def flattened(event):
    """
    Unnest event logs by moving all items at the first level
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


def convert_event_data_to_key_value(event_dict):
    """
    Convert event's data to as key value pair
    Example:
        "@Name": "UtcTime", "#text": "2018-08-21 03:09:31.314" to UtcTime: 2018-08-21 03:09:31.314
    :param event_dict: event
    :return: k,v Data section
    """
    if not 'Data' in event_dict:
        # then return evtx log unchanged
        return event_dict
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


def prepare_event_log(event):
    """
    Prepares event log for use and info extraction. Flattens event log, and converts event
    to key value pair.
    :param event: single Sysmon event from log
    :return: dict, event dict
    """

    flat = flattened(event)
    return convert_event_data_to_key_value(flat)
