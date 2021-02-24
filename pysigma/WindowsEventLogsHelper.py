from xml.parsers.expat import ExpatError
from io import open
from evtx import PyEvtxParser

import collections
import json

def load_events(xmlLog):
    """
    Opens Sysmon xml logs as a readable file, and turns the events into dictionaries

    :param xmlLog: Sysmon xml log to be opened
    :return: dict of the Sysmon event log
    """
    try:
        with open(xmlLog, "r", encoding='utf-8', errors='ignore') as fp:
            magic = fp.read(7)
            fp.seek(0)
            if magic == 'ElfFile':
                # log is evtx type
                parser = PyEvtxParser(xmlLog)
                dictrecords = [json.loads(rec['data']) for rec in parser.records_json()]
                return dictrecords
            else:
                raise Exception('Only EVTX supported')
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


def prepareEventLog(event):
    """
    Prepares event log for use and info extraction. Flattens event log, and converts event
    to key value pair.

    :param event: single Sysmon event from log
    :return: dict, event dict
    """

    flat = flattened(event)
    return flat
