#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime

from typing import Optional
from src.core.logger_config import logger

class Config(object):

    # Connection
    server = Optional[str]
    tls = bool = False
    port = Optional[int]

    # Kerberos
    kerberos = bool = False
    kdc = Optional[str]

    # Credentials
    domain = Optional[str]
    username = Optional[str]
    password = Optional[str]
    nthash = Optional[str]
    aes = Optional[str]
    cert = Optional[str]
    certkey = Optional[str]
    certpass = Optional[str]

    # Ldap specific
    ldapfilter = Optional[str]
    basedn = Optional[str]
    pagesize = Optional[int]
    ldap_currentTime = Optional[datetime]
    allsid = bool = False

    # NTP Sync
    dontfixtime = bool = False
    clockskew = bool = False # True if detected clockskew 

    # Verbose
    quiet = bool = False
    debug = bool = False
    
    # Exec/Interact
    interact = bool = False
    exec = bool = False

    def __init__(self, args):

        # Connection
        self.server = args.server
        self.tls = args.tls
        self.port = args.port

        # Kerberos
        if 'kerberos' in args:
            self.kerberos = args.kerberos
            self.kdc = args.kdc

        # Credentials
        self.domain = args.domain
        self.username = args.username
        self.password = args.password
        self.nthash = args.nthash
        self.aes = args.aes

        # Certificates
        if 'cert' in args:
            self.cert = args.cert
            self.certkey = args.certkey
            self.certpass = args.certpass

        # Ldap specific
        if args.command == 'ldap':
            self.ldapfilter = args.ldapfilter
            self.basedn = args.basedn
            self.userdn = args.userdn
            self.pagesize = args.pagesize
            self.allsid = args.allsid

        # NTP Sync
        self.dontfixtime = args.dontfixtime

        # Verbose
        self.quiet = args.quiet
        self.debug = args.debug
        
        # Exec/Interact
        self.interact = args.interact
        self.exec = args.exec

        self.validate()

    def validate(self):

        if self.nthash :
            # Split hash if lm:nt
            if ':' in self.nthash:
                self.nthash = self.nthash.split(':')[1]

            # Swith to kerberos if AES hash in the NT hash argument
            if len(self.nthash)>32:
                self.kerberos = True
                self.aes = self.nthash
                self.nthash = None
    