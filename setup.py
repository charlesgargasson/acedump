from setuptools import setup, find_packages

setup(
    name='acedump',
    version='0.0.1',
    packages=find_packages(),
    install_requires=[
        'ldap3',
    ],
    entry_points={
        'console_scripts': [
            'acedump=src.main:main',
        ],
    },
)
