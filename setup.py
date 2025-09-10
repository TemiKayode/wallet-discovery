#!/usr/bin/env python3
"""
Setup script for the Crypto Wallet Discovery & Analysis Toolkit.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

# Read requirements
requirements = []
with open("requirements.txt") as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith("#") and not line.endswith("# Built-in with Python"):
            requirements.append(line)

setup(
    name="crypto-wallet-discovery",
    version="1.0.0",
    author="Temi",
    author_email="Temitayokayode5.com",
    description="A comprehensive Python toolkit for discovering, analyzing, and monitoring cryptocurrency wallet addresses across multiple blockchains",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/TemiKayode/wallet-discovery",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Financial and Insurance Industry",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Database",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.991",
        ],
        "ml": [
            "scikit-learn>=1.1.0",
            "numpy>=1.21.0",
            "pandas>=1.4.0",
        ],
        "social": [
            "tweepy>=4.12.0",
            "praw>=7.6.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "wallet-discovery=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.ini", "*.md", "*.txt"],
    },
    keywords="cryptocurrency blockchain wallet discovery analysis monitoring",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/crypto-wallet-discovery/issues",
        "Source": "https://github.com/yourusername/crypto-wallet-discovery",
        "Documentation": "https://github.com/yourusername/crypto-wallet-discovery/blob/main/README.md",
    },
)
