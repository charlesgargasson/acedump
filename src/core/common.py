#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import ipaddress

from src.core.logger_config import logger

def get_acedump_folder():
    acedumpfolder = Path.home().absolute().as_posix() + '/.acedump/'
    Path(acedumpfolder).mkdir(parents=False, exist_ok=True)
    return acedumpfolder

def is_valid_ip(address):
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        return False