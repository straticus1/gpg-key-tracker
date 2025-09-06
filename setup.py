from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="gpg-key-tracker",
    version="1.2.0",
    author="Ryan J Coleman",
    author_email="coleman.ryan@gmail.com",
    description="A comprehensive Python application for managing PGP/GPG keys with metadata tracking and usage logging",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ryancoleman/gpg-key-tracker",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "gpg-tracker=gpg_tracker:cli",
            "gpg-wrapper=gpg_wrapper:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
