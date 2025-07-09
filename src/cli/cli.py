#!/usr/bin/env python3
# -*- coding: utf-8 -*-

### load libfaketime ############
from io import StringIO
import sys
original_stdout = sys.stdout
sys.stdout = StringIO()
from libfaketime import reexec_if_needed
reexec_if_needed()
sys.stdout = original_stdout
#################################

from colorama import Fore, Back, Style

from src.core.logger_config import configure_logger, logger
from src.core.vars import BANNER
from src.cli.arguments import parse_args
from src.core.config import Config

from src.ldap.ldap import handle_ldap
from src.smb.smb import handle_smb
from src.winrm.winrm import handle_winrm

def cli():

    # Print version
    print(Style.BRIGHT + Fore.WHITE + BANNER + Style.RESET_ALL)

    # Retrieve arguments
    args = parse_args()

    # Set debug level
    configure_logger(args)

    # Parse arguments
    config = Config(args)

    match args.command:
        case "ldap":
            handle_ldap(config)
        case "smb":
            handle_smb(config)
        case "winrm":
            handle_winrm(config)

    