#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ldap3
from colorama import Fore, Back, Style

from src.core.logger_config import logger
from src.ldap.aceparse import parse_sd_search_results
from src.core.config import Config
from src.core.vars import SID_DICT

def resolve_sid(config: Config, conn: ldap3.Connection):
    logger.debug(f"\n-- Searching for SIDs")
    cookie = None
    while True:
        sd_search = conn.search(
            search_base=config.basedn,
            search_filter='(objectSid=*)', 
            search_scope=ldap3.SUBTREE,
            attributes=['sAMAccountName', 'name', 'objectClass','objectSid'],
            paged_size=config.pagesize,
            paged_cookie=cookie
        )

        if not sd_search:
            break

        cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        for entry in conn.entries:
            name = entry.sAMAccountName.value or entry.name.value
            if not name:
                logger.debug(f"? {entry.objectSid.value}")
                continue

            obj_class = entry.objectClass.values if entry.objectClass else []

            obj_type = '⚙️ ' 
            if 'msDS-GroupManagedServiceAccount' in obj_class :
                obj_type = '🤖'
            elif 'computer' in obj_class :
                obj_type = '💻'
            elif 'user' in obj_class :
                obj_type = '👤'
            elif 'group' in obj_class:
                obj_type = '📁'
                
            if not entry.objectSid.value in SID_DICT.keys():
                SID_DICT[entry.objectSid.value]=f"{name} {obj_type}"
                logger.debug(f"{obj_type} {entry.objectSid.value:<40}\t{name:<40}\t{obj_class}")

        if not cookie:
            break

    if not config.quiet:
        logger.info("✅ Resolved SIDs " + Style.BRIGHT + Fore.GREEN + f"{len(SID_DICT)}" + Style.RESET_ALL)

def dump_aces(config: Config, conn: ldap3.Connection, filter):
    """Dump all ACEs from AD objects"""

    msg = Style.BRIGHT + Fore.YELLOW 
    msg += f"   Searching objects ... filter: '{filter}'  basedn: '{config.basedn}'"
    msg += Style.RESET_ALL
    logger.debug(msg)

    # Searching with security descriptors
    cookie = None

    while True:
        controls = [('1.2.840.113556.1.4.801', True, bytearray([0x30, 0x03, 0x02, 0x01, 0x07]))]
        sd_search = conn.search(
            search_base=config.basedn,
            search_filter=filter, 
            search_scope=ldap3.SUBTREE,
            attributes=['nTSecurityDescriptor', 'distinguishedName', 'objectClass', 'sAMAccountName'],
            paged_size=int(config.pagesize),
            controls=controls,
            paged_cookie=cookie
        )

        if not sd_search:
            break

        cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        parse_sd_search_results(config, conn)

        if not cookie:
            break