#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime

from typing import Optional
from src.core.logger_config import logger

class Config(object):

    # Hosts
    ldaphost = Optional[str]
    smbhost = Optional[str]
    winrmhost = Optional[str]
    kdchost = Optional[str]

    # Connection
    tls = bool = False
    port = Optional[int]

    # Kerberos
    kerberos = bool = False
    ccache_file = Optional[str]

    # Credentials
    domain = Optional[str]
    username = Optional[str]
    password = Optional[str]
    nthash = ''
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

    # SMB specific
    smbip = None

    def __init__(self, args):

        # Hosts
        if 'ldaphost' in args:
            self.ldaphost = args.ldaphost
        
        if 'smbhost' in args:
            self.smbhost = args.smbhost

        if 'winrmhost' in args:
            self.winrmhost = args.winrmhost

        if 'kdchost' in args:
            self.kdchost = args.kdchost

        # Connection
        if 'tls' in args:
            self.tls = args.tls
        
        if 'port' in args:
            self.port = args.port

        # Kerberos
        if 'kerberos' in args:
            self.kerberos = args.kerberos

        # Credentials
        if 'domain' in args:
            self.domain = args.domain
        
        if 'username' in args:
            self.username = args.username

        if 'password' in args:
            self.password = args.password

        if 'nthash' in args:
            self.nthash = args.nthash

        if 'aes' in args:
            self.aes = args.aes

        # Certificates
        if 'cert' in args:
            self.cert = args.cert
        
        if 'certkey' in args:
            self.certkey = args.certkey
        
        if 'certpass' in args:
            self.certpass = args.certpass

        # Ldap specific
        if 'ldapfilter' in args:
            self.ldapfilter = args.ldapfilter
        
        if 'basedn' in args:
            self.basedn = args.basedn
        
        if 'userdn' in args:
            self.userdn = args.userdn
        
        if 'pagesize' in args:
            self.pagesize = args.pagesize
        
        if 'allsid' in args:
            self.allsid = args.allsid

        # NTP Sync
        if 'dontfixtime' in args:
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
                self.nthash = ''
    