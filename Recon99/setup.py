"""
setup.py
Recon99 — pip-installable package setup
Author: FMShomit
"""

from setuptools import setup, find_packages
from pathlib import Path

long_description = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

setup(
    name="recon99",
    version="1.0.0",
    author="FMShomit",
    description="Automated Reconnaissance & Vulnerability Scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/FMShomit/Recon99",
    packages=find_packages(exclude=["tests*", "reports*"]),
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "dnspython>=2.4.0",
        "python-whois>=0.9.4",
        "rich>=13.7.0",
        "anthropic>=0.25.0",
        "colorama>=0.4.6",
        "urllib3>=2.0.0",
        "lxml>=4.9.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov",
            "black",
            "flake8",
            "mypy",
        ]
    },
    entry_points={
        "console_scripts": [
            "recon99=main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
    ],
    keywords="recon reconnaissance security pentest vulnerability scanner",
    project_urls={
        "Bug Tracker": "https://github.com/FMShomit/Recon99/issues",
    },
)
