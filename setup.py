from setuptools import setup, find_packages

setup(
    name="hardcorde",
    version="1.0.0",
    description="High-confidence credential discovery for authorized penetration tests",
    packages=find_packages(),
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "hardcorde=hardcorde.__main__:main",
        ],
    },
)
