from setuptools import find_packages, setup

setup(
    name="fastguard",
    version="1.0.0",
    packages=find_packages(include=["fastguard*"]),
    install_requires=[
        "typer>=0.9.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "fastguard=fastguard.cli:app",
        ],
    },
    python_requires=">=3.9",
)
