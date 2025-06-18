from setuptools import setup, find_packages

setup(
    name='acedump',
    version='0.0.2',
    packages=find_packages(),
    install_requires=[
        'ldap3',
        'colorama',
        'gssapi',
    ],
    entry_points={
        'console_scripts': [
            'acedump=src.main:main',
        ],
    },
)
