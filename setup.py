from setuptools import setup, find_packages

__version__ = '0.9.2'

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="ddfr",
    version=__version__,
    author="Playtika Ltd.",
    author_email="security@playtika.com",
    description="A lightweight Python utility to detect dns records that are suspected as dangling.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/PlaytikaSecurity/ddfr",
    packages=find_packages(exclude=['tests*']),
    install_requires=requirements,
    python_requires='>=3.7',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        'console_scripts': [
            'ddfr=ddfr.ddfr:interactive',
        ],
    },
)
