#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from libfaketime import fake_time
from impacket.ntlm import compute_nthash
from colorama import Fore, Back, Style

import gssapi
import ldap3
import ssl
import os
from datetime import datetime

from src.core.logger_config import logger
from src.core.common import is_valid_ip
from src.krb.krb import set_krb_config, retrieve_tgt
from src.core.config import Config

def preconnect(config: Config) -> tuple[ldap3.Server, ldap3.Connection]:
    if not config.port:
        if config.tls:
            config.port=636
        else:
            config.port=389

    srv = ldap3.Server(config.ldaphost.upper(), get_info=ldap3.ALL, port=config.port, use_ssl=config.tls)
    if config.cert :
        srv.tls = ldap3.Tls(
            local_private_key_file=config.certkey,
            local_private_key_password=config.certpass,
            local_certificate_file=config.cert,
            validate=ssl.CERT_NONE,
            version=ssl.PROTOCOL_TLS_CLIENT,
            ciphers="ALL:@SECLEVEL=0",
            ssl_options=[ssl.OP_ALL],
        )
    else:
        srv.tls = ldap3.Tls(
            validate=ssl.CERT_NONE,
            version=ssl.PROTOCOL_TLS_CLIENT,
            ciphers="ALL:@SECLEVEL=0",
            ssl_options=[ssl.OP_ALL],
        )

    if not config.quiet:
        logger.info("⚙️  LDAP .. " + Style.BRIGHT + Fore.CYAN + f"{srv}" + Style.RESET_ALL)

    # Retrieve Root DSE informations
    serverName = None
    server_domain = None

    conn = ldap3.Connection(srv, auto_bind=True)
    conn_test = conn.search('', '(objectClass=*)', search_scope='BASE', attributes=[], size_limit=1)
    if not conn_test:
        logger.error(f"❌ Error searching Root DSE")
        logger.error(f"conn.last_error : {conn.last_error}\nconn.result : {conn.result}")
    else:
        if not config.quiet:
            logger.info(f"✅ Available Root DSE")

        logger.debug(srv.info)

        # Retrieve domain, potential hostname and time
        ldap_currentTime_value = srv.info.other.get('currentTime')[0]
        default_naming_context = srv.info.other.get('defaultNamingContext')[0]
        serverName = srv.info.other.get('serverName')[0]

        server_domain = str('.'.join([dc.split('=')[1] for dc in default_naming_context.split(',') if dc.startswith('DC=')])).upper()
        serverName = f"{serverName.split(',')[0].split('=')[1]}.{server_domain}".upper()

        config.ldap_currentTime = datetime.strptime(ldap_currentTime_value, "%Y%m%d%H%M%S.0Z") # .replace(tzinfo=timezone.utc)
        clock_skew_delta = datetime.now() - config.ldap_currentTime
        if int(clock_skew_delta.total_seconds()) > 2 :
            logger.warning("⚠️  LDAP clock in past " + Style.BRIGHT + Fore.YELLOW + f"{config.ldap_currentTime} ({clock_skew_delta.total_seconds()} seconds)" + Style.RESET_ALL)
            config.clockskew = True
        elif int(clock_skew_delta.total_seconds()) < -2 :
            logger.warning("⚠️  LDAP clock in futur " + Style.BRIGHT + Fore.YELLOW + f"{config.ldap_currentTime} ({clock_skew_delta.total_seconds()} seconds)" + Style.RESET_ALL)
            config.clockskew = True
        else:
            if not config.quiet:
                logger.info(f"✅ Synced with LDAP clock : {config.ldap_currentTime} ({clock_skew_delta.total_seconds()} seconds)")

        # Set basedn if missing
        if not config.basedn:
            config.basedn = default_naming_context
        
        # Set domain if missing
        if not config.domain:
            config.domain = server_domain
        
        # Terminate
        conn.unbind()

    # Set user
    user = None
    if config.domain and config.username:
        user = f'{config.domain}\\{config.username}'
    elif not config.domain:
        logger.warning(f"⚠️ Missing Domain")
        if config.username:
            user = config.username

    # Handle TLS + Cert
    if config.cert and config.tls:
        if config.userdn :
            sasl_credentials=f"{config.userdn}"
        else:
            sasl_credentials=()
        conn = ldap3.Connection(srv, user=user, authentication='SASL', sasl_mechanism='EXTERNAL', sasl_credentials=sasl_credentials, auto_bind=False)

    # Kerberos
    elif config.kerberos:
        # Kerberos need the server name
        if serverName:
            config.ldaphost = serverName
        srv.host = config.ldaphost

        conn = ldap3.Connection(srv, authentication='SASL', sasl_mechanism='GSSAPI', sasl_credentials=(), auto_bind=False)

        # Specified KDC
        if config.kdchost:
            config.kdchost = config.kdchost.upper()

        # KDC from server value
        elif not is_valid_ip(config.ldaphost):
            config.kdchost = config.ldaphost

        krb_config_file = os.environ.get("KRB5_CONFIG")
        if not krb_config_file:
            set_krb_config(config, server_domain)

        # Using credentials if specified
        if config.password or config.nthash or config.aes:
            retrieve_tgt(config)
        else:
            ccache_file = os.environ.get("KRB5CCNAME")
            if not ccache_file:
                if user:
                    logger.warning(f"⚠️  Undefined KRB5CCNAME and no given password, login with blank password ...")
                    retrieve_tgt(config)
                else:
                    logger.warning(f"⚠️  No credentials were supplied, login as anonymous ...")
                    conn = ldap3.Connection(srv, authentication='ANONYMOUS')
            else:
                logger.info("♻️  KRB5CCNAME " + Style.BRIGHT + Fore.CYAN + f"{ccache_file}" + Style.RESET_ALL)

    # NTLM / OTHER
    else:
        # Handles hashes for NTLM
        if config.password:
            config.password = f"aad3b435b51404eeaad3b435b51404ee:{compute_nthash(config.password).hex()}"
        elif config.nthash:
            config.password = f"aad3b435b51404eeaad3b435b51404ee:{config.nthash}"
        elif not config.cert and user:
            config.password = f"aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"

        # Cert without TLS
        if config.cert:

            # NTLM Auth + StartTLS
            if config.password and user :
                conn = ldap3.Connection(srv, user=user, password=config.password, authentication='NTLM', auto_bind=False)
           
            # StartTLS with user DN
            elif config.userdn :
                conn = ldap3.Connection(srv, authentication='SASL', sasl_mechanism='EXTERNAL', sasl_credentials=f"{config.userdn}", auto_bind=False)
            
            # StartTLS
            else:
                conn = ldap3.Connection(srv, authentication='SASL', sasl_mechanism='EXTERNAL', sasl_credentials=(), auto_bind=False)
       
        else:

            # Usual NTLM auth
            if config.password and user :
                conn = ldap3.Connection(srv, user=user, password=config.password, authentication='NTLM', auto_bind=False)

            # Blank password
            elif user :
                logger.warning(f"⚠️  Login with blank password ...")
                conn = ldap3.Connection(srv, user=user, password=config.password, authentication='NTLM', auto_bind=False)

            else:
                logger.warning(f"⚠️  No credentials were supplied, login as anonymous ...")
                conn = ldap3.Connection(srv, authentication='ANONYMOUS')
    
    return srv, conn

def connect(config: Config) -> tuple[ldap3.Server, ldap3.Connection]:
    """Connect to server and return conn"""

    srv, conn = preconnect(config)

    if not config.quiet:
        logger.info("\n⚙️  LDAP .. " + Style.BRIGHT + Fore.CYAN + f"{srv}" + Style.RESET_ALL)

    # Fix clock skew
    if config.clockskew and not config.dontfixtime:
        fake_time_obj = fake_time(config.ldap_currentTime, tz_offset=0)
        fake_time_obj.start()

    # Use StartTLS if using certificate on non-TLS
    if not config.tls:
        starttls_oid = '1.3.6.1.4.1.1466.20037'
        if starttls_oid in [x[0] for x in srv.info.supported_extensions]:
            logger.debug(f"⚙️  StartTLS in server supported_extensions, starting..")
            try:
                conn.start_tls()
                logger.info(f"✅ StartTLS")
            except Exception as e:
                if not config.quiet:
                    logger.warning(f"⚠️  StartTLS ({str(e)})")
                conn.session_security=ldap3.ENCRYPT
                #raise

    # Bind
    if config.tls:
        conn.open()
        if conn.closed:
            logger.error(f"❌ LDAP open failed")
            logger.error(f"conn.last_error : {conn.last_error}\nconn.result : {conn.result}")
            return False, False
    else:
        bind_result = conn.bind()
        if not bind_result:
            logger.error(f"❌ LDAP bind failed")
            logger.error(f"conn.last_error : {conn.last_error}\nconn.result : {conn.result}")
            return False, False

    # Release clock skew
    if config.clockskew and not config.dontfixtime:
        fake_time_obj.stop()

    logger.debug(f"✅ {conn}")
    whoami_oid='1.3.6.1.4.1.4203.1.11.3'
    if whoami_oid in [x[0] for x in srv.info.supported_extensions]:
        identity = conn.extend.standard.who_am_i()
        logger.info("✅ Authenticated as " + Style.BRIGHT + Fore.GREEN + f"{identity}" + Style.RESET_ALL)

    # First query after bind/open
    conn_test = conn.search('', '(objectClass=*)', search_scope='BASE', attributes=[], size_limit=1)
    if not conn_test:
        logger.error("❌ Basic search failed")
        logger.error(f"conn.last_error : {conn.last_error}\nconn.result : {conn.result}")
        return False, False

    # Ensure base DN is set
    if not config.basedn:
        config.basedn = srv.info.other.get('defaultNamingContext')[0]
    
    # Validate base DN
    base_test = conn.search(config.basedn, '(objectClass=*)', search_scope='BASE', attributes=['distinguishedName'], size_limit=1)
    if not base_test:
        logger.error(f"❌ Can't search DN {config.basedn}")
        logger.error(f"conn.last_error : {conn.last_error}\nconn.result : {conn.result}")
        return False

    if not config.quiet:
        logger.info("✅ Available DN " + Style.BRIGHT + Fore.GREEN + f"{config.basedn}" + Style.RESET_ALL)
    
    return srv, conn