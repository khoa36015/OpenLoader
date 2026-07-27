from setuptools import setup, find_packages

setup(
    name="openloader",
    version="1.0.0",
    description="Profile-driven PE loader — one JSON controls injection, evasion, permissions, and C++ extensions",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[],
    entry_points={
        "console_scripts": [
            "openloader=generator:main",
        ],
    },
)
