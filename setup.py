#!/usr/bin/env python

from setuptools import setup

with open("README.rst", "r") as f:
    long_description = f.read()

with open("requirements.txt", "r") as f:
    requirements = [l.strip() for l in f if l.strip()]

setup(
    name="kitakubu",
    version="0.9",
    description="Command-line utility for uploading Google Apps Script projects",
    long_description=long_description,
    author="Joe Hu (SAPikachu)",
    author_email="i@sapika.ch",
    url="https://github.com/SAPikachu/kitakubu",
    packages=["kitakubu"],
    install_requires=requirements,
    entry_points={
        "console_scripts": ["kitakubu = kitakubu:main"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Programming Language :: Python :: 2.7",
    ],
)
