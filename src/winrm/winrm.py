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
from libfaketime import fake_time

import sys, os, time
import threading

connection_lock = threading.Lock()
stop_keepalive = threading.Event()
keepalive_interval = 5
last_status='✅'

def command_ls(ps):
    ps.add_script("Get-ChildItem | Format-Table Name, Length, LastWriteTime -AutoSize | Out-String")

commands={
    'ls': command_ls,
    'dir': command_ls,
    'll': command_ls,
}

def get_current_context(pool):
    """Get current username and directory"""
    try:
        # Get current username
        with connection_lock:
            ps = PowerShell(pool)
            ps.add_script("$env:USERNAME")
            ps.invoke()
            username = ps.output[0].strip() if ps.output else "Unknown"
            #ps.output.clear()
            del ps
        
        # Get current directory
        with connection_lock:
            ps = PowerShell(pool)
            ps.add_script("Get-Location | Select-Object -ExpandProperty Path")
            ps.invoke()
            current_dir = ps.output[0].strip() if ps.output else "Unknown"
            #ps.output.clear()
            del ps
        
        return username, current_dir
    except Exception as e:
        print(f"[!] Error getting context: {e}")
        return "Unknown", "Unknown"

def handle_input(pool):
    global last_status
    username, current_dir = get_current_context(pool)
    cmd = input(f"\n{last_status} {username} | {current_dir} > ")
    if stop_keepalive.is_set():
        return

    ps = PowerShell(pool)

    if cmd in commands:
        commands[cmd](ps)
    else:
        ps.add_script(cmd)

    with connection_lock:
        ps.invoke()

    if ps.had_errors:
        last_status='❌'
    else:
        last_status='✅'

    if len(ps.output) > 0 :
        for x in ps.output: 
            print(f'{x}')
    if len(ps.streams.error) > 0:
        for x in ps.streams.error: 
            print(f'❌ {x}')
    if len(ps.streams.debug) > 0:
        for x in ps.streams.warning: 
            print(f'⚠️  {x}')
    if len(ps.streams.debug) > 0:
        for x in ps.streams.verbose: 
            print(f'⚠️  {x}')
    if len(ps.streams.debug) > 0:
        for x in ps.streams.debug: 
            print(f'⚠️  {x}')

    #ps.output.clear()
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
        
        # Fix clock skew
        if config.clockskew and not config.dontfixtime:
            fake_time_obj = fake_time(config.ldap_currentTime, tz_offset=0)
            fake_time_obj.start()

        logger.info("\n⚙️  WINRM (KRB) .. " + Style.BRIGHT + Fore.CYAN + f"{config.winrmhost} {config.winrmip}" + Style.RESET_ALL)
        wsman = WSMan(config.winrmhost, username=config.username, password=None, domain=config.domain, ssl=False, auth=auth, cert_validation=False, negotiate_service=service)
    
        with RunspacePool(wsman) as pool:
            start_keepalive(pool)
            while not stop_keepalive.is_set():
                handle_input(pool)
        
        if config.clockskew and not config.dontfixtime:
            fake_time_obj.stop()
    else:
        logger.info("\n⚙️  WINRM .. " + Style.BRIGHT + Fore.CYAN + f"{config.winrmhost}" + Style.RESET_ALL)
        wsman = WSMan(config.winrmhost, username=config.username, password=config.password, domain=config.domain, ssl=False, auth=auth, cert_validation=False, negotiate_service=service)

        with RunspacePool(wsman) as pool:
            start_keepalive(pool)
            while not stop_keepalive.is_set():
                handle_input(pool)

def keepalive_task(pool):
    """Background keepalive task"""
    fail = 0
    while not stop_keepalive.is_set():
        time.sleep(keepalive_interval)

        try:
            with connection_lock:
                ps = PowerShell(pool)
                ps.add_script("")
                ps.invoke()
            del ps
                
        except Exception as e:
            logger.warning(f"\n⚠️  Keepalive failed: {e}")
            fail += 1
            if fail > 1:
                stop_keepalive.set()
            
def start_keepalive(pool):
    """Start the keepalive thread"""
    keepalive_thread = threading.Thread(
        target=keepalive_task,
        args={pool},
        daemon=True,
        name="WINRM-Keepalive"
    )
    keepalive_thread.start()
    #logger.info(f"Keepalive started with {self.keepalive_interval}s interval")