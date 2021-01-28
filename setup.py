import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="sigma_signature",
    version="0.0.3",
    description="A library for parsing sysmon logs against sigma rules",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages()
)