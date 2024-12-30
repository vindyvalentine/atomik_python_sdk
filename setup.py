from pathlib import Path

from setuptools import find_packages
from setuptools import setup

setup(
    name="atomik_py",
    version="0.0.1",
    description="Python SDK for Atomik API Integration",
    long_description=Path.open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Vindy Valentine",
    author_email="vindyfriendly@gmail.com",
    url="https://github.com/vindyvalentine/atomik_python_sdk",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "pycryptodome>=3.15.0",
    ],
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
