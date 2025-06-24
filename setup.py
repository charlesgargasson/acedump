from setuptools import setup, find_packages

setup(
    name='acedump',
    version='0.0.8',
    packages=find_packages(),
    install_requires=[
        'ldap3',
        'colorama',
        'gssapi',
        'impacket',
        'libfaketime'
    ],
    entry_points={
        'console_scripts': [
            'acedump=src.main:main',
        ],
    },
)
