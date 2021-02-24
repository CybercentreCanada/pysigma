import os.path
import shutil
import urllib.request
import traceback

import pytest

import pysigma


project_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


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


def test_load_sample_rules(upstream_rules):
    processor = pysigma.PySigma()
    unsupported = 0
    failed = 0
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
                traceback.print_exc()
                failed += 1

    print('unsupported', unsupported)
    assert failed == 0
    assert len(processor.rules) > 600

