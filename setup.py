import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open('requirements.txt', 'r') as fh:
    requirements = fh.readlines()


setuptools.setup(
    name="pysigma",
    version="0.0.4",
    description="A library for parsing sysmon logs against sigma rules",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    install_requires=requirements,
    entry_points="""
    [console_scripts]
    sigma-validate=pysigma.validator_cli:main
    """
)
