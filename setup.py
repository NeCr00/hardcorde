from setuptools import setup, find_packages

setup(
    name="hardcorde",
    version="1.1.0",
    description="Cross-platform credential discovery for authorized penetration tests",
    packages=find_packages(),
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "hardcorde=hardcorde.__main__:main",
            "credfinder=hardcorde.__main__:main",
        ],
    },
)
