from collections.abc import MutableMapping
from xml.parsers.expat import ExpatError
from io import open
from evtx import PyEvtxParser

import json
import xmltodict


def load_events(log_file_name):
    """
    Opens Sysmon logs as a readable file, and turns the events into dictionaries
    :param log_file_name: Sysmon evtx or xml log to be opened
    :return: dict of the Sysmon event log
    """
    try:
        with open(log_file_name, "r", encoding='utf-8', errors='ignore') as fp:
            data = fp.read()
            magic = data[:7]
            fp.seek(0)
            if magic == 'ElfFile':
                # log is evtx type
                parser = PyEvtxParser(log_file_name)
                dictrecords = []
                try:
                    for rec in parser.records_json():
                        dictrecords.append(json.loads(rec['data']))
                except RuntimeError:
                    # Parsing error: https://github.com/omerbenamram/evtx/issues/227
                    # Continue with the records that were collected
                    pass
                return dictrecords, 'evtx'
            elif "EventID" in data:
                try:
                    events = xmltodict.parse(data)
                except ExpatError:
                    if data.count('<Event') > 1:
                        # Contains a series of single events but aren't wrapped within an 'Events block'
                        events = xmltodict.parse(f"<Events>{data}</Events>")

                if not events.get('Events'):
                    # Single event was given, modify object to be nested within 'Events' block
                    events = xmltodict.parse(f"<Events>{data}</Events>")
                return events, 'xml'
            else:
                raise TypeError('Unsupported file given')

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
        if isinstance(value, MutableMapping):
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
    if not isinstance(event_dict.get('Data', 0), list):
        # then return evtx log unchanged
        return event_dict
    tempdict = {}
    data = event_dict['Data']
    event_dict.update({'StartModule': None})

    for item in data:
        if not isinstance(item, dict):
            # Unexpected <Data> block format, skipping..
            print("Error in Data Section: Formatting")
            break
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
