#!/usr/bin/env python3
from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="simple_vpn",
    version="0.1.0",
    author="Simple VPN Team",
    author_email="example@example.com",
    description="A simple VPN implementation using OpenVPN",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/username/simple_vpn",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "cryptography>=3.4.0",
        "pyOpenSSL>=20.0.0",
        "python-dotenv>=0.19.0",
        "click>=8.0.0",
        "pystun3>=1.0.0",
        "tqdm>=4.62.0",
        "psutil>=5.8.0"
    ],
    entry_points={
        "console_scripts": [
            "simple-vpn-server=server.server:cli",
            "simple-vpn-client=client.client:cli",
        ],
    },
)
