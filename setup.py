from setuptools import setup, find_packages

setup(
    name='acedump',
    version='1.0.10',
    packages=find_packages(),
    install_requires=[
        'ldap3 @ git+https://github.com/cannatag/ldap3',
        'impacket @ git+https://github.com/fortra/impacket',
        'pypsrp[kerberos] @ git+https://github.com/jborean93/pypsrp',
        'colorama',
        'gssapi',
        'libfaketime',
        'fusepy'
    ],
    entry_points={
        'console_scripts': [
            'acedump=src.cli.cli:cli',
            'ace=src.cli.cli:cli',
        ],
    },
)
