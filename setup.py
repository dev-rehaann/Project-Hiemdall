from setuptools import setup, find_packages

setup(
    name="persistent-threat-hunter",
    version="0.1.0",
    description="UEFI Rootkit and Anti-Forensics Detection Platform",
    author="Your Name",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "click>=8.1.7",
        "rich>=13.7.0",
        "yara-python>=4.3.1",
        "networkx>=3.2.1",
        "jinja2>=3.1.2",
    ],
    entry_points={
        "console_scripts": [
            "pth=main:cli",
        ],
    },
)