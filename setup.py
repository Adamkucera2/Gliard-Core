from setuptools import setup, find_packages

setup(
    name="gliard",
    version="1.0.0",
    packages=find_packages(),
    py_modules=["main"],
    package_data={
        "engine": ["config.yaml"],
    },
    include_package_data=True,
    install_requires=[
        "rich>=13.0.0",
        "fpdf2>=2.7.0",
        "click>=8.0.0",
        "pyyaml>=6.0",
        "requests>=2.31.0",
        "urllib3<2"
    ],
    entry_points={
        "console_scripts": [
            "gliard=main:main",
        ],
    },
)
