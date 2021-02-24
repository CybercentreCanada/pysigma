import os.path
import shutil
import urllib.request

import pytest

import sigma_signature.pysigma


test_dir = os.path.dirname(__file__)


@pytest.fixture
def upstream_rules():
    url = 'https://github.com/Neo23x0/sigma/archive/master.zip'
    zip_path = os.path.join(test_dir, 'neo-sigma-master.zip')
    zip_dir = os.path.join(test_dir, 'neo-sigma-master')
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
    processor = sigma_signature.pysigma.PySigma()
    for file_name in os.listdir(upstream_rules):
        if not file_name.endswith('.yml'):
            continue

        with open(os.path.join(upstream_rules, file_name)) as handle:
            processor.add_signature(handle)


