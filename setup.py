import os
import setuptools
import yaml

from collections import defaultdict
from git import Repo
from json import dumps
from tempfile import TemporaryDirectory


with open("README.md", "r") as fh:
    long_description = fh.read()

with open('requirements.txt', 'r') as fh:
    requirements = fh.readlines()

with TemporaryDirectory() as clone_dir:
    # Create mapping the Sigma library uses and dump to disk
    Repo.clone_from("https://github.com/SigmaHQ/sigma.git", clone_dir)
    master_config = defaultdict(dict)
    for root, dirs, files in os.walk(os.path.join(clone_dir, "tools/config")):
        for file in files:
            if file.endswith('yml'):
                config_dict = {}
                # Parse yaml config file
                with open(os.path.join(root, file), 'r') as fh:
                    config_dict = yaml.safe_load(fh)
                # If it doesn't include logsource, skip
                if 'logsources' not in config_dict.keys():
                    continue

                logsources = config_dict['logsources']
                for category, meta in logsources.items():
                    if 'product' in meta.keys():
                        master_config[meta['product']][category] = meta.get('conditions', {})
    open('pysigma/sigma_configuration.py', 'w').write(
        f"PRODUCT_CATEGORY_MAPPING = {dumps(master_config, indent=4, sort_keys=True)}"
    )


setuptools.setup(
    name="pysigma",
    version="0.0.6",
    description="A library for parsing sysmon logs against sigma rules",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    install_requires=requirements,
    entry_points="""
    [console_scripts]
    sigma-validate=pysigma.validator_cli:main
    sigma-check=pysigma.pysigma:main
    """
)
