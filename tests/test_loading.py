import os.path
import shutil
import urllib.request

import pytest

import pysigma
from pysigma import load_events


project_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
logfile_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'xml_example'))


def build_sysmon_events():
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


@pytest.fixture
def upstream_rules():
    url = 'https://github.com/Neo23x0/sigma/archive/master.zip'
    zip_path = os.path.join(project_dir, 'neo-sigma-master.zip')
    zip_dir = os.path.join(project_dir, 'neo-sigma-master')
    try:
        if not os.path.exists(zip_path):
            urllib.request.urlretrieve(url, zip_path)
        if not os.path.exists(zip_dir):
            shutil.unpack_archive(zip_path, zip_dir)
        return os.path.join(zip_dir, 'sigma-master', 'rules')
    finally:
        pass
        # shutil.rmtree(zip_path, ignore_errors=True)
        # shutil.rmtree(zip_dir, ignore_errors=True)


def test_load_rules(upstream_rules):
    """
    Try to load all the signatures in the base sigma library.
    """
    processor = pysigma.PySigma()
    unsupported = 0
    for dir_path, _, files_in_dir in os.walk(upstream_rules):
        for file_name in files_in_dir:
            if not file_name.endswith('.yml'):
                continue

            try:
                with open(os.path.join(dir_path, file_name)) as handle:
                    processor.add_signature(handle)
            except pysigma.UnsupportedFeature:
                unsupported += 1
            except Exception:
                print("failed on ", dir_path, file_name)
                raise

    print('unsupported', unsupported)
    assert len(processor.rules) > 600


def test_run_rules(upstream_rules):
    """
    Run a sample through all the rules after we load them.

    This isn't meant to actually show that they work. Just that they can be run
    through with any data at all without crashing. We should have other tests
    that specifically target and verify sigma features.
    """
    processor = pysigma.PySigma()
    unsupported = 0
    for dir_path, _, files_in_dir in os.walk(upstream_rules):
        for file_name in files_in_dir:
            if not file_name.endswith('.yml'):
                continue
            try:
                with open(os.path.join(dir_path, file_name)) as handle:
                    processor.add_signature(handle)
            except pysigma.UnsupportedFeature:
                pass

    processor.check_events(build_sysmon_events())
    print('unsupported', unsupported)
    assert len(processor.rules) > 600

