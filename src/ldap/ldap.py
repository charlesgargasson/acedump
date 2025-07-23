#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from colorama import Fore, Back, Style

from src.core.logger_config import logger
from src.core.config import Config
from src.ldap.connect import connect
from src.ldap.common import resolve_sid, dump_aces
from src.ldap.commands import Commands

def handle_ldap(config: Config):

    srv, conn = connect(config)
    if not conn:
        return
    
    resolve_sid(config, conn)

    commands = Commands(config, srv, conn)

    if config.exec:
        commands.exec()
        if not config.interact:
            return
    
    if config.interact:
        commands.interact()
        return
    
    if config.ldapfilter:
        dump_aces(config, conn, config.ldapfilter)
    else:

        logger.info(Style.BRIGHT + Fore.YELLOW + f"\n-- OTHER --" + Style.RESET_ALL)
        dump_aces(config, conn, '(!(|(objectClass=user)(objectClass=computer)(objectClass=group)))')

        logger.info(Style.BRIGHT + Fore.YELLOW + f"\n-- GROUP --" + Style.RESET_ALL)
        dump_aces(config, conn, '(|(objectClass=group))')

        logger.info(Style.BRIGHT + Fore.YELLOW + f"\n-- COMPUTER --" + Style.RESET_ALL)
        dump_aces(config, conn, '(|(objectClass=computer))')

        logger.info(Style.BRIGHT + Fore.YELLOW + f"\n-- USER --" + Style.RESET_ALL)
        dump_aces(config, conn, '(|(objectClass=user))')
    
    conn.unbind()