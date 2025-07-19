#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from src.core.logger_config import logger
from src.core.config import Config
from src.core.common import is_valid_ip
from src.krb.krb import set_krb_config, retrieve_tgt
from src.ldap.connect import preconnect

from pypsrp.wsman import WSMan
from pypsrp.client import Client
from pypsrp.powershell import PowerShell, RunspacePool
from colorama import Fore, Back, Style

import sys, os

def get_current_context(pool):
    """Get current username and directory"""
    try:
        # Get current username
        ps = PowerShell(pool)
        ps.add_script("$env:USERNAME")
        ps.invoke()
        username = ps.output[0].strip() if ps.output else "Unknown"
        ps.output.clear()
        del ps
        
        # Get current directory
        ps = PowerShell(pool)
        ps.add_script("Get-Location | Select-Object -ExpandProperty Path")
        ps.invoke()
        current_dir = ps.output[0].strip() if ps.output else "Unknown"
        ps.output.clear()
        del ps
        
        return username, current_dir
    except Exception as e:
        print(f"[!] Error getting context: {e}")
        return "Unknown", "Unknown"

def handle_input(pool):
    username, current_dir = get_current_context(pool)
    
    cmd = input(f"\n{username} | {current_dir} > ")
    ps = PowerShell(pool)
    ps.add_script(cmd)
    ps.invoke()
    if ps.had_errors:
        print('[!] Error')
    else:
        print('[*] Success')
    if len(ps.output) > 0 :
        for x in ps.output: 
            print(x)
    if len(ps.streams.debug) > 0:
        print(f"[*] Printing streams debug")
        for x in ps.streams.debug: 
            print(x)
    ps.output.clear()
    del ps

def handle_winrm(config: Config):
    auth="negotiate"
    service="HTTP"

    if config.kerberos:
        if not config.winrmip:
            if is_valid_ip(config.winrmhost):
                config.winrmip = config.winrmhost
                config.winrmhost = socket.gethostbyaddr(config.winrmip)[0]
            else:
                config.winrmip = socket.gethostbyname(config.winrmhost)

        if not config.domain:
            logger.error('❌ Missing Domain')
            sys.exit(1)

        config.ldaphost = config.domain
        preconnect(config)

        ccache_file = os.environ.get("KRB5CCNAME")
        if not ccache_file:
            logger.error("❌ Connection failed")
        
        logger.info("\n⚙️  WINRM (KRB) .. " + Style.BRIGHT + Fore.CYAN + f"{config.winrmhost} {config.winrmip}" + Style.RESET_ALL)
        wsman = WSMan(config.winrmhost, username=config.username, password=None, domain=config.domain, ssl=False, auth=auth, cert_validation=False, negotiate_service=service)
    
    else:
        logger.info("\n⚙️  WINRM .. " + Style.BRIGHT + Fore.CYAN + f"{config.winrmhost}" + Style.RESET_ALL)
        wsman = WSMan(config.winrmhost, username=config.username, password=config.password, domain=config.domain, ssl=False, auth=auth, cert_validation=False, negotiate_service=service)

    with RunspacePool(wsman) as pool:
        while True:
            handle_input(pool)
