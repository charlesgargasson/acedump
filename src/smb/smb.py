#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from src.core.logger_config import logger
from src.core.config import Config

from impacket import smb
from impacket.smbconnection import SMBConnection
from src.krb.krb import set_krb_config, retrieve_tgt
import os

def share_access(conn: SMBConnection, share_name):

    sharewrite = False
    shareread = False

    if share_name.upper() in ['IPC$']:
        return shareread, sharewrite 
    
    try:
        conn.listPath(share_name, '*')
        shareread = True

        test_dir = f"test_write_ace_{os.urandom(4).hex()}"
        conn.createDirectory(share_name, test_dir)
        conn.deleteDirectory(share_name, test_dir)
        sharewrite = False

    except Exception as e:
        pass

    return shareread, sharewrite 

def handle_share(conn: SMBConnection, share):
    share_name = share['shi1_netname'][:-1]  # Remove null terminator
    share_type = share['shi1_type']
    share_comment = share['shi1_remark'][:-1] if share['shi1_remark'] else ''
    
    # Determine share type
    if share_type == smb.SHARED_DISK:
        type_str = "DISK"
    elif share_type == smb.SHARED_PRINT_QUEUE:
        type_str = "PRINTER"
    elif share_type == smb.SHARED_DEVICE:
        type_str = "DEVICE"
    elif share_type == smb.SHARED_IPC:
        type_str = "IPC"
    else:
        type_str = "UNKNOWN"

    shareread, sharewrite = share_access(conn, share_name)
    shareread = 'R' if shareread else '-'
    sharewrite = 'W' if sharewrite else '-'
    shareaccess = f"{shareread}{sharewrite}"
    
    print(f"{shareaccess:>10}  {share_name:<15} {type_str:<10} {share_comment}")

def handle_shares(conn: SMBConnection):
    shares = conn.listShares()
    print(f"{'ACCESS':>10}  {'SHARE':<15} {'TYPE':<10} {'COMMENT'}")
    for share in shares:
        handle_share(conn, share)

def smb_infos(conn: SMBConnection):
    logger.info(f'[+] {conn.getServerDNSHostName()} -- {conn.getServerOS()} (Signing:{conn.isSigningRequired()}) (LoginRequired:{conn.isLoginRequired()})')

def connect(config: Config) -> SMBConnection:

    if not config.username:
        config.username = ''

    if not config.password:
        config.password = ''

    if config.kerberos:
        if not config.kdchost:
            logger.error('Missing KDC')
            os.exit(1)

        if not config.domain:
            logger.error('Missing Domain')
            os.exit(1)

        krb_config_file = os.environ.get("KRB5_CONFIG")
        if not krb_config_file:
            set_krb_config(config, config.domain)

        ccache_file = os.environ.get("KRB5CCNAME")

        conn = SMBConnection(config.smbhost)
        if not ccache_file:
            connected = conn.kerberosLogin(config.username, config.password, config.domain, lmhash='', nthash=config.nthash, aesKey=config.aes, kdcHost=config.kdchost)
        else:
            connected = conn.kerberosLogin(config.username, config.password, kdcHost=config.kdchost)
    else:
        conn = SMBConnection(config.smbhost, config.smbhost)
        connected = conn.login(config.username, config.password)

    return connected, conn

def handle_smb(config: Config):

    try:
        connected, conn = connect(config)
    except Exception as e:
        print(f"[-] {str(e)}")
        return

    if not connected:
        return
    
    smb_infos(conn)
    handle_shares(conn)

    
    conn.close()

