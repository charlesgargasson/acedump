#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal
from impacket.krb5.constants import PrincipalNameType

from libfaketime import fake_time
from colorama import Fore, Back, Style

import os

from src.core.logger_config import logger
from src.core.config import Config
from src.core.common import get_acedump_folder

def set_krb_config(config: Config, server_domain):
    krb_config =   '[libdefaults]' + '\n'
    krb_config += f'default_realm = {server_domain}' + '\n'
    krb_config += f'dns_canonicalize_hostname = false' + '\n'
    krb_config += f'rdns = false' + '\n\n'

    krb_config += f'[realms]' + '\n'
    krb_config += f'{server_domain} = '+r'{' + '\n'
    krb_config += f'kdc = {config.kdchost}' + '\n'
    krb_config += f'admin_server = {config.kdchost}' + '\n'
    krb_config += r'}' + '\n\n'

    krb_config += f'[domain_realm]' + '\n'
    krb_config += f'{server_domain} = {server_domain}' + '\n'
    krb_config += f'.{server_domain} = {server_domain}' + '\n'

    krb_config_file = get_acedump_folder() + 'krb.conf'

    with open(krb_config_file, "w") as f:
        f.write(krb_config)

    os.environ["KRB5_CONFIG"] = krb_config_file

    if not config.quiet:
        logger.info("🛠️  KRB5_CONFIG " + Style.BRIGHT + Fore.CYAN + f"{krb_config_file}" + Style.RESET_ALL)

def retrieve_tgt(config):
    """Retrieve a Kerberos TGT and save it to a ccache file"""

    if not config.quiet:
        logger.info("\n⚙️  Connecting to KDC .. " + Style.BRIGHT + Fore.CYAN + f"{config.kdchost}" + Style.RESET_ALL)

    try:
        # Create user principal
        user_principal = Principal(config.username, type=PrincipalNameType.NT_PRINCIPAL.value)

        aesKey = None
        nthash = ''
        lmhash = ''

        if config.nthash:
            lmhash = bytes.fromhex('aad3b435b51404eeaad3b435b51404ee')
            nthash = bytes.fromhex(config.nthash)
        elif config.aes:
            aesKey = str(config.aes)
        elif not config.password:
            lmhash = bytes.fromhex('aad3b435b51404eeaad3b435b51404ee')
            nthash = bytes.fromhex('31d6cfe0d16ae931b73c59d7e0c089c0')  

        # Get TGT
        #freezer = freeze_time(ldap_currentTime)
        #freezer.start()
        if config.clockskew and not config.dontfixtime:
            fake_time_obj = fake_time(config.ldap_currentTime, tz_offset=0)
            fake_time_obj.start()

        tgt, cipher, old_session_key, session_key = getKerberosTGT(
            clientName = user_principal,
            password = config.password,
            domain = config.domain,
            lmhash = lmhash,
            nthash = nthash,
            aesKey = aesKey,
            kdcHost = config.kdchost,
            serverName = None,
        )

        if config.clockskew and not config.dontfixtime:
            fake_time_obj.stop()

        # Save ticket to ccache
        ccache = CCache()
        ccache.fromTGT(tgt, old_session_key, old_session_key)

        ccache_file = get_acedump_folder() + f"{config.username}.ccache"
        ccache.saveFile(ccache_file)
        config.ccache_file = ccache_file

        if not config.quiet:
            logger.info("✅ CCache saved to " + Style.BRIGHT + Fore.GREEN + f"{ccache_file}" + Style.RESET_ALL)

        os.environ["KRB5CCNAME"] = 'FILE:'+ccache_file
        return

    except Exception as e:
        logger.error(f"❌ Asking TGT \n{str(e)}")
        raise