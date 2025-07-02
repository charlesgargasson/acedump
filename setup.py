from setuptools import setup, find_packages

setup(
    name='acedump',
    version='0.0.11',
    packages=find_packages(),
    install_requires=[
        'ldap3 @ git+https://github.com/cannatag/ldap3',
        'impacket @ git+https://github.com/fortra/impacket',
        'colorama',
        'gssapi',
        'libfaketime'
    ],
    entry_points={
        'console_scripts': [
            'acedump=src.main:main',
        ],
    },
)
