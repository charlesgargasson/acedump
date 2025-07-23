#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
from colorama import Fore, Back, Style
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives import serialization
from typing import Optional

from src.core.logger_config import logger
from src.core.common import get_acedump_folder

class Config(object):

    # Hosts
    ldaphost = Optional[str]
    ldapip = Optional[str]

    smbhost = Optional[str]
    smbip = Optional[str]

    winrmhost = Optional[str]
    winrmip = Optional[str]

    kdchost = Optional[str]
    kdcip = Optional[str]

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
    
        if type(self.cert) == str:
            if self.cert[-4:] in ['.pfx','.PFX', '.p12']:
                logger.debug(f"📜 PFX {self.cert}")

                with open(self.cert, "rb") as f:
                    pfx_data = f.read()
                
                if type(self.certpass) == str:
                    self.certpass = self.certpass.encode()
                else:
                    self.certpass = None

                private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(pfx_data, self.certpass)
                self.certpass = None # Reset password
                pem_key = private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=NoEncryption()
                )

                logger.info(f"📜 Issuer " + Style.BRIGHT + Fore.CYAN + certificate.issuer.rfc4514_string() + Style.RESET_ALL)
                logger.info(f"📜 Subject " + Style.BRIGHT + Fore.CYAN + certificate.subject.rfc4514_string() + Style.RESET_ALL)

                san_ext = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san = san_ext.value
                for gn in san:
                    if isinstance(gn, x509.OtherName):
                        try:
                            decoded = gn.value.decode("utf-8").strip()
                            logger.info(f"📜 SubjectAlternativeName " + Style.BRIGHT + Fore.CYAN + decoded + Style.RESET_ALL)
                        except UnicodeDecodeError:
                            logger.info(f"📜 SubjectAlternativeName " + Style.BRIGHT + Fore.CYAN + f"{gn.value!r}" + Style.RESET_ALL )

                pem_cert = certificate.public_bytes(Encoding.PEM)

                certdir = get_acedump_folder() + 'data'
                self.cert=f"{certdir}/cert.pem"
                with open(self.cert, "wb") as cert_file:
                    cert_file.write(pem_cert)
                    logger.info(f"📜 Extracted PEM " + Style.BRIGHT + Fore.CYAN + f"{self.cert}" + Style.RESET_ALL)

                self.certkey=f"{certdir}/key.pem"
                with open(self.certkey, "wb") as key_file:
                    key_file.write(pem_key)
                    logger.info(f"📜 Extracted KEY " + Style.BRIGHT + Fore.CYAN + f"{self.certkey}" + Style.RESET_ALL)